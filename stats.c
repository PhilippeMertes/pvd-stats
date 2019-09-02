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

#include <pcap.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <json-c/json.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <math.h>

#include "stats.h"


#define TIMEOUT 10


void free_stats(t_pvd_stats **stats, int size) {
	t_pvd_info *info = NULL;
	for (int i = 0; i < size; ++i) {
	    // free PvD info
		info = &stats[i]->info;
		free(info->name);
		for (int j = 0; info->addr[j] != NULL; ++j) {
			free(info->addr[j]);
		}

		// free flow structure linked-list
		t_pvd_flow *flow = stats[i]->flow;
		t_pvd_flow *next_flow;
		while(flow != NULL) {
			next_flow = flow->next;
			free(flow->ts);
			free(flow);
			flow = next_flow;
		}

		// destroy mutexes
		pthread_mutex_destroy(&stats[i]->mutex);
		pthread_mutex_destroy(&stats[i]->mutex_acked);
	}
}


int add_flow(t_pvd_stats *stats, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t seq,
	const u_int32_t exp_ack, const struct timeval ts) {
	int empty_list = 0;
	// if there is no element in the linked list
	if (stats->flow == NULL) {
		++empty_list;
		stats->flow = malloc(sizeof(t_pvd_flow));
		if (stats->flow == NULL) {
			fprintf(stderr, "Unable to allocate memory to store the network flow information\n");
			return EXIT_FAILURE;
		}
		stats->flow->next = NULL;
	}

	t_pvd_flow *flow = stats->flow;
	t_pvd_flow *prev_flow = NULL;
	/* get to the last element of the linked list,
	   while deleting elements with a timestamp older than TIMEOUT */
	while (flow->next != NULL) {
		if (ts.tv_sec - flow->ts->tv_sec > TIMEOUT) {
			// the first element should be removed
			if (prev_flow == NULL) {
				stats->flow = flow->next;
				free(flow->ts);
				free(flow);
				flow = stats->flow;
			} // an element in the middle will be removed
			else {
				prev_flow->next = flow->next;
				free(flow->ts);
				free(flow);
				flow = prev_flow->next;
			}
		} // the element is up-to-date
		else {
			prev_flow = flow;
			flow = flow->next;
		}
	}

	if (!empty_list) {
		// allocate memory
		flow->next = malloc(sizeof(t_pvd_flow));
		if (flow->next == NULL) {
			fprintf(stderr, "Unable to allocate memory to store the network flow information\n");
			return EXIT_FAILURE;
		}
		flow = flow->next;
	}
	
	flow->ts = malloc(sizeof(struct timeval));
	if (flow->ts == NULL) {
		fprintf(stderr, "Unable to allocate memory to store the network flow information\n");
		return EXIT_FAILURE;
	}

	// add values to the new element
	memcpy(flow->src_ip, src_ip, 16);
	memcpy(flow->dst_ip, dst_ip, 16);
	flow->src_port = src_port;
	flow->dst_port = dst_port;
	flow->seq = seq;
	flow->exp_ack = exp_ack;
	flow->ts->tv_sec = ts.tv_sec;
	flow->ts->tv_usec = ts.tv_usec;
	flow->next = NULL;

	return EXIT_SUCCESS;
}


void remove_flow(t_pvd_stats *stats, t_pvd_flow *flow_to_rem) {
	t_pvd_flow *flow = stats->flow;
	t_pvd_flow *prev_flow = NULL;
	
	while (flow != NULL) {
		// if we found the element to remove
		if (flow == flow_to_rem) {
			// the first element should be removed
			if (prev_flow == NULL) {
				stats->flow = flow->next;
				free(flow->ts);
				free(flow);
				flow = stats->flow;
			} // an element in the middle will be removed
			else {
				prev_flow->next = flow->next;
				free(flow->ts);
				free(flow);
				flow = prev_flow->next;
			}
			break;
		} // visit the next element
		else {
			prev_flow = flow;
			flow = flow->next;
		}
	}
}


t_pvd_flow *find_flow(t_pvd_flow *flow, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const u_int32_t ack) {

	while(flow != NULL) {	
		if (!memcmp(flow->src_ip, src_ip, 16) && !memcmp(flow->dst_ip, dst_ip, 16)
			&& flow->src_port == src_port && flow->dst_port == dst_port && flow->exp_ack == ack)
			break;
		flow = flow->next;
	}

	return flow;
}


void update_rtt(t_pvd_max_min_avg *rtt, t_pvd_flow *flow, struct timeval ts) {
	double curr_rtt = (ts.tv_sec + ts.tv_usec * pow(10, -6))
	                  - (flow->ts->tv_sec + flow->ts->tv_usec * pow(10, -6)); // RTT in secs
	rtt->min = (curr_rtt < rtt->min || rtt->min == 0) ? curr_rtt : rtt->min;
	rtt->max = (curr_rtt > rtt->max) ? curr_rtt: rtt->max;
	rtt->avg = ((double)(rtt->nb) * rtt->avg + curr_rtt) / (double) (rtt->nb+1);
	++rtt->nb;
}
