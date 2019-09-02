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

/**
 * Holds general information concerning a PvD
 */
typedef struct pvd_info {
	char *name;
	char **addr;
} t_pvd_info;

/**
 * Holds average, maximum, minimum values
 */
typedef struct pvd_max_min_avg {
	double avg;
	double max;
	double min;
	unsigned long nb;
} t_pvd_max_min_avg;

/**
 * Identifies a network flow.
 * Holds source and destination port, IP address, timestamp,
 * sequence number and expected ACK number
 */
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

/**
 * Holds the statistics for a PvD.
 * Additionally, holds a linked-list of network flows and mutex variables.
 */
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


/**
 * Frees the memory allocated by an array of #t_pvd_stats structures
 *
 * @param stats array pointer
 * @param size array size
 */
void free_stats(t_pvd_stats **stats, int size);

/**
 * Adds a flow to the stats->flow linked-list of network flows.
 *
 * @param stats #t_pvd_stats structure holding statistics for one PvD
 * @param src_ip source IPv6 address
 * @param dst_ip destination IPv6 address
 * @param src_port source port
 * @param dst_port destination port
 * @param seq sequence number
 * @param exp_ack expected acknowledgement number
 * @param ts timestamp
 * @return integer representing the success of the operation (EXIT_SUCCESS/EXIT_FAILURE)
 */
int add_flow(t_pvd_stats *stats, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t seq,
	const u_int32_t exp_ack, const struct timeval ts);

/**
 * Removes a flow from the stats->flow linked list.
 *
 * @param stats #t_pvd_stats structure holding statistics for one PvD
 * @param flow_to_rem pointer to the element to be removed
 */
void remove_flow(t_pvd_stats *stats, t_pvd_flow *flow_to_rem);

/**
 * Find the element of the linked-list of flows, to which
 * the flow with the following specifications is acknowledging to.
 *
 * @param flow #t_pvd_flow linked-list
 * @param src_ip source IPv6 address
 * @param dst_ip destination IPv6 address
 * @param src_port source port
 * @param dst_port destination port
 * @param ack acknowledgement number
 * @return pointer to the #t_pvd_flow element
 */
t_pvd_flow *find_flow(t_pvd_flow *flow, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t ack);

/**
 * Update the average, maximum and minimum values for the Round-Trip Time.
 *
 * @param rtt #t_pvd_max_min structure holding average, max, min values for the RTT
 * @param flow values specific to a network flow
 * @param ts timestamp
 */
void update_rtt(t_pvd_max_min_avg *rtt, t_pvd_flow *flow, struct timeval ts);
