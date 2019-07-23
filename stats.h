/*
 * Copyright (c) 2019, Philippe Mertes <mertesph@hotmail.de>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pthread.h>

typedef struct pvd_info {
	char *name;
	char **addr;
} t_pvd_info;

typedef struct pvd_max_min_avg {
	double avg;
	double max;
	double min;
	unsigned long nb;
} t_pvd_max_min_avg;

typedef struct pvd_flow {
	u_int8_t src_ip[16];
	u_int8_t dst_ip[16];
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int32_t seq;
	u_int32_t exp_ack;
	struct timeval *ts;
	struct pvd_flow *next;
} t_pvd_flow;

typedef struct pvd_stats {
	t_pvd_info info;
	unsigned long rcvd_cnt;
	unsigned long snt_cnt;
	t_pvd_max_min_avg tput[3]; // [0] = general, [1] = upload, [2] = download
	t_pvd_max_min_avg rtt[3]; // [0] = general, [1] = upload, [2] = download
	t_pvd_flow *flow;
	pthread_mutex_t mutex;
	pthread_mutex_t mutex_acked;
	u_int32_t acked_bytes[3];
} t_pvd_stats;

void free_stats(t_pvd_stats **stats, int size);

int add_flow(t_pvd_stats *stats, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t seq, const u_int32_t exp_ack, const struct timeval ts);

void remove_flow(t_pvd_stats *stats, t_pvd_flow *flow_to_rem);

t_pvd_flow *find_flow(t_pvd_flow *flow, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t ack);

void update_rtt(t_pvd_max_min_avg *rtt, t_pvd_flow *flow, struct timeval ts);
