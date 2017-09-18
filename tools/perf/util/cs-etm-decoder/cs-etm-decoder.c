/*
 * Copyright(C) 2015-2017 Linaro Limited. All rights reserved.
 * Author: Tor Jeremiassen <tor@ti.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU GEneral Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/err.h>
#include <linux/list.h>
#include <stdlib.h>

#include "cs-etm.h"
#include "cs-etm-decoder.h"
#include "c_api/opencsd_c_api.h"
#include "etmv4/trc_pkt_types_etmv4.h"
#include "ocsd_if_types.h"
#include "util.h"


#define MAX_BUFFER 1024

struct cs_etm_decoder;

struct cs_etm_channel {
	struct cs_etm_decoder	*decoder;
	uint8_t			cs_id;
	struct list_head	chan_list;
};

struct cs_etm_decoder {
	struct cs_etm_state	state;
	dcd_tree_handle_t	dcd_tree;
	void			(*packet_printer)(const char *);
	cs_etm_mem_cb_type	mem_access;
	ocsd_datapath_resp_t	prev_return;
	size_t			prev_processed;
	bool			trace_on;
	bool			discontinuity;
	struct cs_etm_packet	packet_buffer[MAX_BUFFER];
	uint32_t		packet_count;
	uint32_t		head;
	uint32_t		tail;
	uint32_t		end_tail;
	struct list_head	channel_list;
};

static uint32_t cs_etm_decoder__mem_access(const void *context,
					   const ocsd_vaddr_t address,
					   const ocsd_mem_space_acc_t mem_space,
					   const uint32_t req_size,
					   uint8_t *buffer)
{
	struct cs_etm_decoder *decoder = (struct cs_etm_decoder *) context;
	(void) mem_space;

	return decoder->mem_access(decoder->state.data,
				   address,
				   req_size,
				   buffer);
}

int cs_etm_decoder__add_mem_access_cb(struct cs_etm_decoder *decoder,
				      uint64_t start, uint64_t end,
				      cs_etm_mem_cb_type cb_func)
{
	int err;

	decoder->mem_access = cb_func;
	err = ocsd_dt_add_callback_mem_acc(decoder->dcd_tree, start, end,
					   OCSD_MEM_SPACE_ANY,
					   cs_etm_decoder__mem_access,
					   decoder);
	if (err)
		return -CS_ETM_ERR_DECODER;

	return 0;
}

int cs_etm_decoder__get_packet(struct cs_etm_decoder *decoder,
			       struct cs_etm_packet *packet)
{
	if (!decoder)
		return -CS_ETM_ERR_PARAM;

	if (decoder->packet_count == 0)
		return -CS_ETM_ERR_NODATA;

	if (!packet)
		return -CS_ETM_ERR_PARAM;

	*packet = decoder->packet_buffer[decoder->head];

	decoder->head = (decoder->head + 1) & (MAX_BUFFER - 1);

	decoder->packet_count--;

	return 0;
}

const struct cs_etm_state *
cs_etm_decoder__process_data_block(struct cs_etm_decoder *decoder,
				   uint64_t indx, const uint8_t *buf,
				   size_t len, size_t *consumed)
{
	int ret = 0;
	ocsd_datapath_resp_t dp_ret = decoder->prev_return;
	size_t processed = 0;

	if (!decoder)
		return NULL;

	if (decoder->packet_count > 0) {
		decoder->state.err = ret;
		*consumed = processed;
		return &decoder->state;
	}

	while ((processed < len) && (ret == 0)) {
		if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
			dp_ret = ocsd_dt_process_data(decoder->dcd_tree,
						      OCSD_OP_FLUSH,
						      0,
						      0,
						      NULL,
						      NULL);
			break;
		} else if (OCSD_DATA_RESP_IS_CONT(dp_ret)) {
			uint32_t count;

			dp_ret = ocsd_dt_process_data(decoder->dcd_tree,
						      OCSD_OP_DATA,
						      indx + processed,
						      len - processed,
						      &buf[processed],
						      &count);
			processed += count;
		} else {
			ret = -CS_ETM_ERR_DECODER;
		}

	}
	/*
	 * Adjust the counts of processed and previously processed
	 * data based on the return code and previous return code..
	 */
	if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
		if (OCSD_DATA_RESP_IS_CONT(decoder->prev_return))
			decoder->prev_processed = processed;
		processed = 0;
	} else if (OCSD_DATA_RESP_IS_WAIT(decoder->prev_return)) {
		processed = decoder->prev_processed;
		decoder->prev_processed = 0;
	}
	*consumed = processed;
	decoder->prev_return = dp_ret;
	decoder->state.err = ret;
	return &decoder->state;
}

static void cs_etm_decoder__gen_etmv4_config(struct cs_etm_trace_params *params,
					     ocsd_etmv4_cfg *config)
{
	config->reg_configr = params->reg_configr;
	config->reg_traceidr = params->reg_traceidr;
	config->reg_idr0 = params->reg_idr0;
	config->reg_idr1 = params->reg_idr1;
	config->reg_idr2 = params->reg_idr2;
	config->reg_idr8 = params->reg_idr8;
	config->reg_idr9 = 0;
	config->reg_idr10 = 0;
	config->reg_idr11 = 0;
	config->reg_idr12 = 0;
	config->reg_idr13 = 0;
	config->arch_ver = ARCH_V8;
	config->core_prof = profile_CortexA;
}

static ocsd_datapath_resp_t
cs_etm_decoder__etmv4i_packet_printer(const void *context,
				      const ocsd_datapath_op_t op,
				      const ocsd_trc_index_t indx,
				      const ocsd_etmv4_i_pkt *pkt)
{
	const size_t PACKET_STR_LEN = 1024;
	ocsd_datapath_resp_t ret = OCSD_RESP_CONT;
	char packet_str[PACKET_STR_LEN];
	size_t offset;
	struct cs_etm_channel *channel = (struct cs_etm_channel *) context;
	struct cs_etm_decoder *decoder = channel->decoder;

	sprintf(packet_str, "%ld: id[%02X] ", (long int) indx, channel->cs_id);
	offset = strlen(packet_str);

	switch (op) {
	case OCSD_OP_DATA:
		if (ocsd_pkt_str(OCSD_PROTOCOL_ETMV4I,
				 (void *)pkt, packet_str + offset,
				 PACKET_STR_LEN - offset) != OCSD_OK)
			ret = OCSD_RESP_FATAL_INVALID_PARAM;
		break;
	case OCSD_OP_EOT:
		sprintf(packet_str, "**** END OF TRACE id[%02X] ****\n",
			channel->cs_id);
		break;
	case OCSD_OP_FLUSH:
		sprintf(packet_str, "**** FLUSH DECODER id[%02X] ****\n",
			channel->cs_id);
		break;
	case OCSD_OP_RESET:
		sprintf(packet_str, "**** RESET DECODER ****\n");
		break;
	default:
		break;
	}

	decoder->packet_printer(packet_str);

	return ret;
}

struct cs_etm_channel *cs_etm_decoder__create_channel_item(
						struct cs_etm_decoder *decoder,
						uint8_t cs_id)
{
	struct cs_etm_channel *chan;

	chan = (struct cs_etm_channel *) zalloc(sizeof(*chan));
	if (!chan)
		return NULL;

	chan->decoder = decoder;
	chan->cs_id = cs_id;
	list_add(&(chan->chan_list), &(decoder->channel_list));
	return chan;
}

static int cs_etm_decoder__create_etmv4i_packet_printer(
					struct cs_etm_decoder_params *d_params,
					struct cs_etm_trace_params *t_params,
					struct cs_etm_decoder *decoder)
{
	ocsd_etmv4_cfg trace_config;
	int ret = 0;
	unsigned char CSID; /* CSID extracted from the config data */
	struct cs_etm_channel *channel;

	if (!d_params->packet_printer)
		return -CS_ETM_ERR_PARAM;

	cs_etm_decoder__gen_etmv4_config(t_params, &trace_config);

	decoder->packet_printer = d_params->packet_printer;

	ret = ocsd_dt_create_decoder(decoder->dcd_tree,
				     OCSD_BUILTIN_DCD_ETMV4I,
				     OCSD_CREATE_FLG_PACKET_PROC,
				     (void *)&trace_config, &CSID);

	if (ret != 0)
		return -CS_ETM_ERR_DECODER;

	channel = cs_etm_decoder__create_channel_item(decoder, CSID);
	if (!channel)
		return -CS_ETM_ERR_DECODER;

	ret = ocsd_dt_attach_packet_callback(decoder->dcd_tree,
					  CSID, OCSD_C_API_CB_PKT_SINK,
					  cs_etm_decoder__etmv4i_packet_printer,
					  channel);

	if (ret != 0)
		return -CS_ETM_ERR_DECODER;

	return 0;
}

int
cs_etm_decoder__create_etmv4i_decoder(struct cs_etm_decoder_params *d_params,
				      struct cs_etm_trace_params *t_params,
				      struct cs_etm_decoder *decoder)
{
	int ret;

	if (d_params->operation == CS_ETM_OPERATION_PRINT)
		ret = cs_etm_decoder__create_etmv4i_packet_printer(d_params,
								   t_params,
								   decoder);
	else
		ret = -CS_ETM_ERR_PARAM;

	return ret;
}

struct cs_etm_decoder *
cs_etm_decoder__new(uint32_t num_cpu, struct cs_etm_decoder_params *d_params,
		    struct cs_etm_trace_params t_params[])
{
	struct cs_etm_decoder *decoder;
	ocsd_dcd_tree_src_t format;
	uint32_t flags;
	int ret;
	size_t i;

	if ((!t_params) || (!d_params))
		return NULL;

	decoder = zalloc(sizeof(*decoder));

	if (!decoder)
		return NULL;

	/* init the channel list */
	INIT_LIST_HEAD(&(decoder->channel_list));

	decoder->state.data = d_params->data;
	decoder->prev_return = OCSD_RESP_CONT;
	format = (d_params->formatted ? OCSD_TRC_SRC_FRAME_FORMATTED :
					 OCSD_TRC_SRC_SINGLE);
	flags = 0;
	flags |= (d_params->fsyncs ? OCSD_DFRMTR_HAS_FSYNCS : 0);
	flags |= (d_params->hsyncs ? OCSD_DFRMTR_HAS_HSYNCS : 0);
	flags |= (d_params->frame_aligned ? OCSD_DFRMTR_FRAME_MEM_ALIGN : 0);

	/* Drivers may add barrier frames when used with perf, set up to
	 * handle this. Barriers const of FSYNC packet repeated 4 times.
	 */
	flags |= OCSD_DFRMTR_RESET_ON_4X_FSYNC;

	/* Create decode tree for the data source */
	decoder->dcd_tree = ocsd_create_dcd_tree(format, flags);

	if (decoder->dcd_tree == 0)
		goto err_free_decoder;

	for (i = 0; i < num_cpu; i++) {
		switch (t_params[i].protocol) {
		case CS_ETM_PROTO_ETMV4i:
			ret = cs_etm_decoder__create_etmv4i_decoder(
								d_params,
								&t_params[i],
								decoder);
			if (ret != 0)
				goto err_free_decoder_tree;
			break;
		default:
			goto err_free_decoder_tree;
		}
	}

	return decoder;

err_free_decoder_tree:
	ocsd_destroy_dcd_tree(decoder->dcd_tree);
err_free_decoder:
	free(decoder);
	return NULL;
}

void cs_etm_decoder__free(struct cs_etm_decoder *decoder)
{
	struct cs_etm_channel	*tmp;
	struct list_head	*pos, *q;

	if (!decoder)
		return;

	ocsd_destroy_dcd_tree(decoder->dcd_tree);
	decoder->dcd_tree = NULL;

	list_for_each_safe(pos, q, &(decoder->channel_list)) {
		tmp = list_entry(pos, struct cs_etm_channel, chan_list);
		list_del(pos);
		free(tmp);
	}

	free(decoder);
}
