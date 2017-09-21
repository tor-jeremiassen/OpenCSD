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
