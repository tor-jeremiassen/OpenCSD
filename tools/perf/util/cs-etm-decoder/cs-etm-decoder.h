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

#ifndef INCLUDE__CS_ETM_DECODER_H__
#define INCLUDE__CS_ETM_DECODER_H__

#include <linux/types.h>
#include <stdio.h>

struct cs_etm_decoder;

struct cs_etm_buffer {
	const unsigned char	*buf;
	size_t			len;
	uint64_t		offset;
	uint64_t		ref_timestamp;
};

enum cs_etm_sample_type {
	CS_ETM_RANGE		= 1 << 0,
};

struct cs_etm_state {
	int			err;
	void			*data;
	unsigned int		isa;
	uint64_t		start;
	uint64_t		end;
	uint64_t		timestamp;
};

struct cs_etm_packet {
	enum cs_etm_sample_type	sample_type;
	uint64_t		start_addr;
	uint64_t		end_addr;
	bool			exc;
	bool			exc_ret;
	int			cpu;
};

struct cs_etm_queue;

typedef uint32_t (*cs_etm_mem_cb_type)(struct cs_etm_queue *, uint64_t,
				       size_t, uint8_t *);

struct cs_etm_trace_params {
	void			*etmv4i_packet_handler;
	uint32_t		reg_idr0;
	uint32_t		reg_idr1;
	uint32_t		reg_idr2;
	uint32_t		reg_idr8;
	uint32_t		reg_configr;
	uint32_t		reg_traceidr;
	int			protocol;
};

struct cs_etm_decoder_params {
	int			operation;
	void			(*packet_printer)(const char *);
	cs_etm_mem_cb_type	mem_acc_cb;
	bool			formatted;
	bool			fsyncs;
	bool			hsyncs;
	bool			frame_aligned;
	void			*data;
};


/* Error return codes */
enum {
	CS_ETM_ERR_NOMEM = 1,
	CS_ETM_ERR_NODATA,
	CS_ETM_ERR_PARAM,
	CS_ETM_ERR_OVERFLOW,
	CS_ETM_ERR_DECODER,
};

/*
 * The following enums are indexed starting with 1 to align with the
 * open source coresight trace decoder library.
 */

enum {
	CS_ETM_PROTO_ETMV3 = 1,
	CS_ETM_PROTO_ETMV4i,
	CS_ETM_PROTO_ETMV4d,
};

enum {
	CS_ETM_OPERATION_PRINT = 1,
	CS_ETM_OPERATION_DECODE,
};

struct cs_etm_channel;

struct cs_etm_channel *cs_etm_decoder__create_channel_item(
						struct cs_etm_decoder *decoder,
						uint8_t cs_id);
const struct cs_etm_state *
cs_etm_decoder__process_data_block(struct cs_etm_decoder *decoder,
				   uint64_t indx, const uint8_t *buf,
				   size_t len, size_t *consumed);

struct cs_etm_decoder *
cs_etm_decoder__new(uint32_t num_cpu,
		    struct cs_etm_decoder_params *d_params,
		    struct cs_etm_trace_params t_params[]);

void cs_etm_decoder__free(struct cs_etm_decoder *decoder);

int cs_etm_decoder__add_mem_access_cb(struct cs_etm_decoder *decoder,
				      uint64_t start, uint64_t end,
				      cs_etm_mem_cb_type cb_func);

int
cs_etm_decoder__create_etmv4i_decoder(struct cs_etm_decoder_params *d_params,
				      struct cs_etm_trace_params *t_params,
				      struct cs_etm_decoder *decoder);
#endif /* INCLUDE__CS_ETM_DECODER_H__ */
