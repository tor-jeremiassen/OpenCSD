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
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	auxtrace_heap__free(&aux->heap);
	cs_etm__free_events(session);
	session->auxtrace = NULL;

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
	(void) session;
	(void) event;
	(void) tool;
	return 0;
}

int cs_etm__process_auxtrace_info(union perf_event *event,
				  struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t event_header_size = sizeof(struct perf_event_header);
	size_t info_header_size;
	size_t total_size = auxtrace_info->header.size;
	struct cs_etm_auxtrace *etm = NULL;
	int err = 0;

	/*
	 * sizeof(auxtrace_info_event::type) +
	 * sizeof(auxtrace_info_event::reserved) == 8
	 */
	info_header_size = 8;

	if (total_size < (event_header_size + info_header_size))
		return -EINVAL;

	etm = zalloc(sizeof(*etm));

	if (!etm)
		return -ENOMEM;

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

	return err;
}
