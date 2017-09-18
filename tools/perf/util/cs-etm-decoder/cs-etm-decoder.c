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
