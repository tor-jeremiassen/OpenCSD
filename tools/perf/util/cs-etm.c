/*
 * Copyright(C) 2015-2017 Linaro Limited. All rights reserved.
 * Author: Tor Jeremiassen <tor@ti.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>

#include <stdlib.h>

#include "auxtrace.h"
#include "color.h"
#include "cs-etm.h"
#include "cs-etm-decoder/cs-etm-decoder.h"
#include "debug.h"
#include "evlist.h"
#include "intlist.h"
#include "machine.h"
#include "perf.h"
#include "thread.h"
#include "thread_map.h"
#include "thread-stack.h"
#include "util.h"

struct cs_etm_auxtrace {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	u64				**metadata;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	struct perf_evsel		*switch_evsel;
	struct thread			*unknown_thread;
	uint32_t			num_cpu;
	bool				timeless_decoding;
	bool				sampling_mode;
	bool				snapshot_mode;
	bool				data_queued;
	bool				synth_needs_swap;
	bool				sample_instructions;
	u64				instructions_sample_type;
	u64				instructions_sample_period;
	u64				instructions_id;
	struct itrace_synth_opts	synth_opts;
	unsigned int			pmu_type;
	u64				kernel_start;
};

struct cs_etm_queue {
	struct cs_etm_auxtrace		*etm;
	unsigned int			queue_nr;
	struct auxtrace_buffer		*buffer;
	const struct cs_etm_state	*state;
	union perf_event		*event_buf;
	bool				on_heap;
	bool				step_through_buffers;
	bool				use_buffer_pid_tid;
	pid_t				pid, tid;
	int				cpu;
	struct thread			*thread;
	u64				time;
	u64				timestamp;
	bool				stop;
	struct cs_etm_decoder		*decoder;
	u64				offset;
	bool				eot;
};

static void cs_etm__packet_dump(const char *pkt_string)
{
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color, "	%s\n", pkt_string);
	fflush(stdout);
}

void cs_etm__dump_event(struct cs_etm_auxtrace *etm,
			struct auxtrace_buffer *buffer)
{
	const char *color = PERF_COLOR_BLUE;
	struct cs_etm_decoder_params d_params;
	struct cs_etm_trace_params *t_params;
	struct cs_etm_decoder *decoder;
	size_t buffer_used = 0;
	size_t i;

	fprintf(stdout, "\n");
	color_fprintf(stdout, color,
		     ". ... CoreSight ETM Trace data: size %zu bytes\n",
		     buffer->size);

	/* Use metadata to fill in trace parameters for trace decoder */
	t_params = zalloc(sizeof(*t_params) * etm->num_cpu);
	for (i = 0; i < etm->num_cpu; i++) {
		t_params[i].protocol = CS_ETM_PROTO_ETMV4i;
		t_params[i].reg_idr0 = etm->metadata[i][CS_ETMV4_TRCIDR0];
		t_params[i].reg_idr1 = etm->metadata[i][CS_ETMV4_TRCIDR1];
		t_params[i].reg_idr2 = etm->metadata[i][CS_ETMV4_TRCIDR2];
		t_params[i].reg_idr8 = etm->metadata[i][CS_ETMV4_TRCIDR8];
		t_params[i].reg_configr = etm->metadata[i][CS_ETMV4_TRCCONFIGR];
		t_params[i].reg_traceidr =
					etm->metadata[i][CS_ETMV4_TRCTRACEIDR];
	}

	/* Set decoder parameters to simply print the trace packets */
	d_params.packet_printer = cs_etm__packet_dump;
	d_params.operation = CS_ETM_OPERATION_PRINT;
	d_params.formatted = true;
	d_params.fsyncs = false;
	d_params.hsyncs = false;
	d_params.frame_aligned = true;

	decoder = cs_etm_decoder__new(etm->num_cpu, &d_params, t_params);

	zfree(&t_params);

	if (!decoder)
		return;
	do {
		size_t consumed;
		const struct cs_etm_state *state;

		state = cs_etm_decoder__process_data_block(
				decoder, buffer->offset,
				&((uint8_t *)buffer->data)[buffer_used],
				buffer->size - buffer_used, &consumed);
		if (state && state->err)
			break;

		buffer_used += consumed;
	} while (buffer_used < buffer->size);

	cs_etm_decoder__free(decoder);
}

static int cs_etm__flush_events(struct perf_session *session,
				struct perf_tool *tool)
{
	(void) session;
	(void) tool;
	return 0;
}

static void cs_etm__free_queue(void *priv)
{
	struct cs_etm_queue *etmq = priv;

	if (!etmq)
		return;

	thread__zput(etmq->thread);
	free(etmq);
}

static void cs_etm__free_events(struct perf_session *session)
{
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	struct auxtrace_queues *queues = &aux->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		cs_etm__free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}

	auxtrace_queues__free(queues);
}

static void cs_etm__free(struct perf_session *session)
{
	size_t i;
	struct int_node *inode, *tmp;
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	auxtrace_heap__free(&aux->heap);
	cs_etm__free_events(session);
	session->auxtrace = NULL;

	/* First remove all traceID/CPU# nodes for the RB tree */
	intlist__for_each_entry_safe(inode, tmp, traceid_list)
		intlist__remove(traceid_list, inode);
	/* Then the RB tree itself */
	intlist__delete(traceid_list);

	for (i = 0; i < aux->num_cpu; i++)
		zfree(&aux->metadata[i]);

	zfree(&aux->metadata);
	zfree(&aux);
}

static int cs_etm__process_event(struct perf_session *session,
				 union perf_event *event,
				 struct perf_sample *sample,
				 struct perf_tool *tool)
{
	(void) session;
	(void) event;
	(void) sample;
	(void) tool;
	return 0;
}

static int cs_etm__process_auxtrace_event(struct perf_session *session,
					  union perf_event *event,
					  struct perf_tool *tool)
{
	struct cs_etm_auxtrace *etm = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);

	(void) tool;

	if (!etm->data_queued) {
		struct auxtrace_buffer *buffer;
		off_t  data_offset;
		int fd = perf_data_file__fd(session->file);
		bool is_pipe = perf_data_file__is_pipe(session->file);
		int err;

		if (is_pipe)
			data_offset = 0;
		else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = auxtrace_queues__add_event(&etm->queues, session,
						 event, data_offset, &buffer);
		if (err)
			return err;

		if (dump_trace)
			if (auxtrace_buffer__get_data(buffer, fd)) {
				cs_etm__dump_event(etm, buffer);
				auxtrace_buffer__put_data(buffer);
			}
	}
	return 0;
}

static const char * const cs_etm_global_header_fmts[] = {
	[CS_HEADER_VERSION_0]	= "	Header version		       %llx\n",
	[CS_PMU_TYPE_CPUS]	= "	PMU type/num cpus	       %llx\n",
	[CS_ETM_SNAPSHOT]	= "	Snapshot		       %llx\n",
};

static const char * const cs_etm_priv_fmts[] = {
	[CS_ETM_MAGIC]		= "	Magic number		       %llx\n",
	[CS_ETM_CPU]		= "	CPU			       %lld\n",
	[CS_ETM_ETMCR]		= "	ETMCR			       %llx\n",
	[CS_ETM_ETMTRACEIDR]	= "	ETMTRACEIDR		       %llx\n",
	[CS_ETM_ETMCCER]	= "	ETMCCER			       %llx\n",
	[CS_ETM_ETMIDR]		= "	ETMIDR			       %llx\n",
};

static const char * const cs_etmv4_priv_fmts[] = {
	[CS_ETM_MAGIC]		= "	Magic number		       %llx\n",
	[CS_ETM_CPU]		= "	CPU			       %lld\n",
	[CS_ETMV4_TRCCONFIGR]	= "	TRCCONFIGR		       %llx\n",
	[CS_ETMV4_TRCTRACEIDR]	= "	TRCTRACEIDR		       %llx\n",
	[CS_ETMV4_TRCIDR0]	= "	TRCIDR0			       %llx\n",
	[CS_ETMV4_TRCIDR1]	= "	TRCIDR1			       %llx\n",
	[CS_ETMV4_TRCIDR2]	= "	TRCIDR2			       %llx\n",
	[CS_ETMV4_TRCIDR8]	= "	TRCIDR8			       %llx\n",
	[CS_ETMV4_TRCAUTHSTATUS] = "	TRCAUTHSTATUS		       %llx\n",
};

static void cs_etm__print_auxtrace_info(u64 *val, size_t num)
{
	unsigned int i, j, cpu;

	for (i = 0; i < CS_HEADER_VERSION_0_MAX; i++)
		fprintf(stdout, cs_etm_global_header_fmts[i], val[i]);

	for (i = CS_HEADER_VERSION_0_MAX, cpu = 0; cpu < num; cpu++) {
		if (val[i] == __perf_cs_etmv3_magic)
			for (j = 0; j < CS_ETM_PRIV_MAX; j++, i++)
				fprintf(stdout, cs_etm_priv_fmts[j], val[i]);
		else if (val[i] == __perf_cs_etmv4_magic)
			for (j = 0; j < CS_ETMV4_PRIV_MAX; j++, i++)
				fprintf(stdout, cs_etmv4_priv_fmts[j], val[i]);
		else
			/* failure.. return */
			return;
	}
}

int cs_etm__process_auxtrace_info(union perf_event *event,
				  struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t event_header_size = sizeof(struct perf_event_header);
	size_t info_header_size;
	size_t total_size = auxtrace_info->header.size;
	size_t priv_size = 0;
	size_t num_cpu;
	struct cs_etm_auxtrace *etm = NULL;
	int err = 0, idx = -1;
	u64 *ptr;
	u64 *hdr = NULL;
	u64 **metadata = NULL;
	size_t i, j, k;
	unsigned int pmu_type;
	struct int_node *inode;

	/*
	 * sizeof(auxtrace_info_event::type) +
	 * sizeof(auxtrace_info_event::reserved) == 8
	 */
	info_header_size = 8;

	if (total_size < (event_header_size + info_header_size))
		return -EINVAL;

	priv_size = total_size - event_header_size - info_header_size;

	/* First the global part */
	ptr = (u64 *) auxtrace_info->priv;

	if (ptr[0] != 0)
		return -EINVAL;

	hdr = zalloc(sizeof(*hdr) * CS_HEADER_VERSION_0_MAX);
	if (!hdr)
		return -ENOMEM;

	for (i = 0; i < CS_HEADER_VERSION_0_MAX; i++)
		hdr[i] = ptr[i];
	num_cpu = hdr[CS_PMU_TYPE_CPUS] & 0xffffffff;
	pmu_type = (unsigned int) ((hdr[CS_PMU_TYPE_CPUS] >> 32) &
				    0xffffffff);

	/*
	 * Create an RB tree for traceID-CPU# tuple. Since the conversion has
	 * to be made for each packet that gets decoded, optimizing access in
	 * anything other than a sequential array is worth doing.
	 */
	traceid_list = intlist__new(NULL);
	if (!traceid_list) {
		err = -ENOMEM;
		goto err_free_hdr;
	}

	metadata = zalloc(sizeof(*metadata) * num_cpu);
	if (!metadata) {
		err = -ENOMEM;
		goto err_free_traceid_list;
	}

	/*
	 * The metadata is stored in the auxtrace_info section and encodes
	 * the configuration of the ARM embedded trace macrocell which is
	 * required by the trace decoder to properly decode the trace due
	 * to its highly compressed nature.
	 */
	for (j = 0; j < num_cpu; j++) {
		if (ptr[i] == __perf_cs_etmv3_magic) {
			metadata[j] = zalloc(sizeof(*metadata[j]) *
					     CS_ETM_PRIV_MAX);
			if (!metadata[j]) {
				err = -ENOMEM;
				goto err_free_metadata;
			}
			for (k = 0; k < CS_ETM_PRIV_MAX; k++)
				metadata[j][k] = ptr[i + k];

			/* The traceID is our handle */
			idx = metadata[j][CS_ETM_ETMTRACEIDR];
			i += CS_ETM_PRIV_MAX;
		} else if (ptr[i] == __perf_cs_etmv4_magic) {
			metadata[j] = zalloc(sizeof(*metadata[j]) *
					     CS_ETMV4_PRIV_MAX);
			if (!metadata[j]) {
				err = -ENOMEM;
				goto err_free_metadata;
			}
			for (k = 0; k < CS_ETMV4_PRIV_MAX; k++)
				metadata[j][k] = ptr[i + k];

			/* The traceID is our handle */
			idx = metadata[j][CS_ETMV4_TRCTRACEIDR];
			i += CS_ETMV4_PRIV_MAX;
		}

		/* Get an RB node for this CPU */
		inode = intlist__findnew(traceid_list, idx);

		/* Something went wrong, no need to continue */
		if (!inode) {
			err = PTR_ERR(inode);
			goto err_free_metadata;
		}

		/*
		 * The node for that CPU should not be taken.
		 * Back out if that's the case.
		 */
		if (inode->priv) {
			err = -EINVAL;
			goto err_free_metadata;
		}
		/* All good, associate the traceID with the CPU# */
		inode->priv = &metadata[j][CS_ETM_CPU];
	}

	/*
	 * Each of CS_HEADER_VERSION_0_MAX, CS_ETM_PRIV_MAX and
	 * CS_ETMV4_PRIV_MAX mark how many double words are in the
	 * global metadata, and each cpu's metadata respectively.
	 * The following tests if the correct number of double words was
	 * present in the auxtrace info section.
	 */
	if (i * 8 != priv_size) {
		err = -EINVAL;
		goto err_free_metadata;
	}

	if (dump_trace)
		cs_etm__print_auxtrace_info(auxtrace_info->priv, num_cpu);

	etm = zalloc(sizeof(*etm));

	if (!etm) {
		err = -ENOMEM;
		goto err_free_metadata;
	}

	err = auxtrace_queues__init(&etm->queues);
	if (err)
		goto err_free_etm;

	etm->unknown_thread = thread__new(999999999, 999999999);
	if (!etm->unknown_thread) {
		err = -ENOMEM;
		goto err_free_queues;
	}

	err = thread__set_comm(etm->unknown_thread, "unknown", 0);
	if (err)
		goto err_delete_thread;

	etm->session = session;
	etm->machine = &session->machines.host;
	etm->kernel_start = machine__kernel_start(etm->machine);

	if (thread__init_map_groups(etm->unknown_thread,
				    etm->machine)) {
		err = -ENOMEM;
		goto err_delete_thread;
	}

	etm->num_cpu = num_cpu;
	etm->pmu_type = pmu_type;
	etm->snapshot_mode = (hdr[CS_ETM_SNAPSHOT] != 0);
	etm->timeless_decoding = true;
	etm->sampling_mode = false;
	etm->metadata = metadata;
	etm->auxtrace_type = auxtrace_info->type;

	etm->auxtrace.process_event	     = cs_etm__process_event;
	etm->auxtrace.process_auxtrace_event = cs_etm__process_auxtrace_event;
	etm->auxtrace.flush_events	     = cs_etm__flush_events;
	etm->auxtrace.free_events	     = cs_etm__free_events;
	etm->auxtrace.free		     = cs_etm__free;
	session->auxtrace = &etm->auxtrace;

	if (dump_trace)
		return 0;

	err = auxtrace_queues__process_index(&etm->queues, session);
	if (err)
		goto err_delete_thread;

	etm->data_queued = etm->queues.populated;

	return 0;

err_delete_thread:
	thread__delete(etm->unknown_thread);
err_free_queues:
	auxtrace_queues__free(&etm->queues);
	session->auxtrace = NULL;
err_free_etm:
	zfree(&etm);
err_free_metadata:
	/* No need to check @metadata[j], free(NULL) is supported */
	for (j = 0; j < num_cpu; j++)
		free(metadata[j]);
	zfree(&metadata);
err_free_traceid_list:
	intlist__delete(traceid_list);
err_free_hdr:
	zfree(&hdr);

	return err;
}
