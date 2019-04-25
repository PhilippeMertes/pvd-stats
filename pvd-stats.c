#include <libpvd.h>
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <json-c/json.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "json-handler.h"

#define PVDD_PORT 10101
#define LEN_SLL 16
#define LEN_IPV6 40
#define SOCKET_FILE "/tmp/pvd-stats.uds"
#define SOCKET_BUFSIZE 1024

static pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
static t_pvd_stats **stats;
static unsigned int stats_size = 0;


t_pvd_list *get_pvd_list() {
	t_pvd_connection *conn = pvd_connect(PVDD_PORT);
	t_pvd_list *list = malloc(sizeof(t_pvd_list));

	if(pvd_get_pvd_list_sync(conn, list)) {
		fprintf(stderr, "get_pvd_list: Error while retrieving PvDs list.\n"
			"Make sure that pvdd is running on port %d\n", PVDD_PORT);
		free(list);
		return NULL;
	}

	pvd_disconnect(conn);
	return list;
}


int get_pvd_attribute(t_pvd_list *list, char *pvdname, char *attr) {	
	t_pvd_connection *conn = pvd_connect(PVDD_PORT);

	char *attr_val = NULL;
	if (pvd_get_attribute_sync(conn, pvdname, attr, &attr_val)) {
		fprintf(stderr, "Unable to get the attribute %s from the PvD %s\n", attr, pvdname);
		pvd_disconnect(conn);
		free(attr_val);
		return EXIT_FAILURE;
	}
	pvd_disconnect(conn);

	printf("pvd_get_attribute_sync passed. attr_val: %s\n", attr_val);
	char **attributes = json_handler_parse_string_array(attr_val);
	free(attr_val);

	if (attributes == NULL) {
		return EXIT_FAILURE;
	}

	for (int i = 0; attributes[i] != NULL; ++i) {
		printf("%s\n", attributes[i]);
		free(attributes[i]);
	}
	free(attributes);

	return EXIT_SUCCESS;
}



char **get_pvd_addresses(char *pvdname) {
	t_pvd_connection *conn = pvd_connect(PVDD_PORT);

	char *addr_json = NULL;
	if (pvd_get_attribute_sync(conn, pvdname, "addresses", &addr_json)) {
		fprintf(stderr, "get_pvd_addresses: Unable to get the addresses from the PvD %s\n through pvdd\n",
				pvdname);
		pvd_disconnect(conn);
		free(addr_json);
		return NULL;
	}
	pvd_disconnect(conn);

	char **addr = json_handler_parse_addr_array(addr_json);
	free(addr_json);

	return addr;
}



struct linux_sll {
	u_int16_t packet_type;
	u_int16_t arphrd_type;
	u_int16_t addr_len;
	unsigned char addr[8];
	u_int16_t protocol;
};

void print_ip6_addr(const u_int8_t addr[16]) {
	for (int i = 0; i < 16; ++i) {
		printf("%x", addr[i]);
		if (i % 2 == 1 && i != 15)
			printf(":");
	}
}


void print_flow(t_pvd_flow *flow) {
	printf("[");

	while(flow != NULL) {	
		printf("\n(");
		print_ip6_addr(flow->src_ip);
		printf(", ");
		print_ip6_addr(flow->dst_ip);
		printf(", %d, %d, %u, %u, %ld, %ld)", flow->src_port, flow->dst_port, flow->seq, flow->exp_ack,
			flow->ts->tv_sec, flow->ts->tv_usec);
		flow = flow->next;
	}
	printf("\n]\n");

}


void pcap_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	t_pvd_stats *stats = (t_pvd_stats *) args;

	//printf("ts_sec = %ld, ts_usec = %ld, len = %d\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->len);
	// ==== link-layer header ====
	struct linux_sll *sll = (struct linux_sll *) packet;
	// packet received or sent
	int rcvd = (ntohs(sll->packet_type) != 4);
	if (rcvd)
		++stats->rcvd_cnt;
	else 
		++stats->snt_cnt;

	// check if the network payload is really IPv6
	if (ntohs(sll->protocol) != ETHERTYPE_IPV6)
		return;


	// ==== network-layer header ====
	struct ip6_hdr *ip = (struct ip6_hdr *) &packet[LEN_SLL];
	/*
	printf("src ip: ");
	print_ip6_addr(ip->ip6_src.s6_addr);
	printf("\n");
	printf("dst ip: ");
	print_ip6_addr(ip->ip6_dst.s6_addr);
	printf("\n");
	*/

	// check if packet contains some transport-layer payload
	if (ntohs(ip->ip6_plen) == 0)
		return;

	// ==== TCP transport-layer ====
	if (ip->ip6_nxt == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) &packet[LEN_SLL+LEN_IPV6];
		/*
		printf("source port: %d\n", ntohs(tcp->source));
		printf("dest port: %d\n", ntohs(tcp->dest));
		printf("window: %d\n", ntohs(tcp->window));
		printf("data offset: %d\n", tcp->doff);
		printf("SEQ: %u\n", ntohl(tcp->seq));
		printf("ACK_SEQ: %u\n", ntohl(tcp->ack_seq));
		printf("SYN: %d\n", tcp->syn);
		printf("ACK: %d\n", tcp->ack);
		printf("FIN: %d\n", tcp->fin);
		*/

		// we don't take TCP handshake flows into account
		if (tcp->syn)
			return;

		// find the flow to which we ack
		t_pvd_flow *flow = find_flow(stats->flow, ip->ip6_dst.s6_addr, ip->ip6_src.s6_addr,
			ntohs(tcp->dest), ntohs(tcp->source), ntohl(tcp->ack_seq));
		//print_flow(stats->flow);

		if (flow) {
			pthread_mutex_lock(&stats->mutex);
			//printf("Flow found. Calculating throughput and RTT\n");
			update_rtt(&stats->rtt[0], flow, pkthdr->ts);
			// if we received the packet, then it is an ACK to an uploaded packet
			if (rcvd) {
				//printf("UPLOAD\n");
				update_rtt(&stats->rtt[1], flow, pkthdr->ts);
			}
			else {
				//printf("DOWNLOAD\n");
				update_rtt(&stats->rtt[2], flow, pkthdr->ts);
			}
			pthread_mutex_unlock(&stats->mutex);
			

			pthread_mutex_lock(&stats->mutex_acked);
			// count acked bytes
			u_int32_t acked = (flow->exp_ack >= flow->seq) ? flow->exp_ack - flow->seq : 4294967295 - flow->seq + flow->exp_ack + 1;
			stats->acked_bytes[0] += acked;
			if (rcvd)
				stats->acked_bytes[1] += acked;
			else
				stats->acked_bytes[2] += acked;
			pthread_mutex_unlock(&stats->mutex_acked);
			remove_flow(stats, flow);
		}

		// calculate expected ACK
		u_int32_t seq = ntohl(tcp->seq);
		u_int32_t ack = seq;
		ack += pkthdr->len - LEN_SLL - LEN_IPV6 - tcp->doff * 4; // TCP payload
		//printf("Expected ack: %u\n", ack);
		// If the packet contains no payload, it doesn't need to be acked by the other side.
		// Thus, we don't need to keep track of it.
		if (seq != ack) {
			add_flow(stats, ip->ip6_src.s6_addr, ip->ip6_dst.s6_addr, ntohs(tcp->source), ntohs(tcp->dest), seq, ack, pkthdr->ts);
		}
	}
	//printf("\n");
}


char *construct_filter(char **addr) {
	// detect filter length
	int filt_len = snprintf(NULL, 0, "dst or src host %s", addr[0]);
	for (int i = 1; addr[i] != NULL; ++i)
		filt_len += snprintf(NULL, 0, " or %s", addr[i]);
	if (filt_len < 0) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "Error while constructing packet filter\n");
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		return NULL;
	}
	// create filter
	char *filter = malloc(++filt_len * sizeof(char));
	int pos = sprintf(filter, "dst or src host %s", addr[0]);
	for (int i = 1; addr[i] != NULL; ++i)
		pos += sprintf(&filter[pos], " or %s", addr[i]);
	return filter;
}


static int create_local_socket() {
	int s;
	struct sockaddr_un addr;
	mode_t curr_mask;

	if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		return -1;

	unlink(SOCKET_FILE);

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, SOCKET_FILE);

	curr_mask = umask(011); // needed so that non-root users can connect to socket
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr))){
		close(s);
		return -1;
	}
	umask(curr_mask);

	if (listen(s, 10)) {
		close(s);
		return -1;
	}

	return s;
}


static void handle_socket_connection(int welcome_sock) {
	int sock;
	struct sockaddr_in addr;
	socklen_t addr_len;
	char *buffer = malloc(SOCKET_BUFSIZE);
	ssize_t size;
	json_object *json = NULL;
	char delim[] = " \n";
	char *cmd;
	char *pvd;

	printf("stats[0] name:%s\n", stats[0]->info.name);

	addr_len = sizeof(struct sockaddr_in);

	if ((sock = accept(welcome_sock, (struct sockaddr *) &addr, &addr_len)) <= 0) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "Error while accepting client connection: %s\n", strerror(errno));
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		return;
	}

	size = recv(sock, buffer, SOCKET_BUFSIZE-1, 0);
	if (size < 0) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "Error while reading message sent to the socket: %s\n", strerror(errno));
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		close(sock);
		return;
	}

	buffer[size] = '\0';
	fprintf(stdout, "Message received: %s\n", buffer);
	fflush(stdout);

	cmd = strtok(buffer, delim);
	pvd = strtok(NULL, delim);

	t_pvd_stats *pvd_stats = NULL;

	if (pvd) {
		// find stats corresponding to the pvd
		for (int i = 0; i < stats_size; ++i) {
			if (strcmp(stats[i]->info.name, pvd) == 0)
				pvd_stats = stats[i];
		}
		if (!pvd_stats) {
			// the given pvd is not known
			sprintf(buffer, "{\"error\": \"unknown cmd/pvd\"}");
			send(sock, buffer, strlen(buffer)+1, 0);
			free(buffer);
			close(sock);
			return;
		}
	}
	
	// If no PvD is specified, stats for all the PvDs should be retrieved and, thus, we need to lock all of them
	if (!pvd) {
		for (int i = 0; i < stats_size; ++i)
			pthread_mutex_lock(&stats[i]->mutex);
	} else {
		// only lock mutex for this specific PvD
		pthread_mutex_lock(&pvd_stats->mutex);
	}

	if (strcmp(cmd, "all") == 0) {
		json = (pvd) ? json_handler_all_stats_one_pvd(pvd_stats) : json_handler_all_stats(stats, stats_size);
	}
	else if (strcmp(cmd, "rtt") == 0) {
		json = (pvd) ? json_handler_rtt_stats_one_pvd(pvd_stats) : json_handler_rtt_stats(stats, stats_size);
	}
	else if (strcmp(cmd, "tput") == 0) {
		json = (pvd) ? json_handler_tput_stats_one_pvd(pvd_stats) : json_handler_tput_stats(stats, stats_size);
	}

	// unlocking mutex(es)
	if (!pvd) {
		for (int i = 0; i < stats_size; ++i)
			pthread_mutex_unlock(&stats[i]->mutex);
	} else {
		pthread_mutex_unlock(&pvd_stats->mutex);
	}

	if (json != NULL) {
		const char *json_str = json_object_to_json_string_ext(json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY);
		printf("%s\n", json_str);
		send(sock, json_str, strlen(json_str)+1, 0);
	}
	else {
		sprintf(buffer, "{\"error\": \"unknown command\nYou can only retrieve stats for [all] [rtt] [tput]\"}");
		send(sock, buffer, strlen(buffer)+1, 0);
	}

	json_object_put(json);
	free(buffer);
	close(sock);
}


static void *socket_communication() {
	int welcome_sock = create_local_socket();
	if (welcome_sock < 0) {
		perror("Unable to create local welcome socket\n");
		exit(EXIT_FAILURE);
	}

	while(1) {
		handle_socket_connection(welcome_sock);
	}
	
	close(welcome_sock);
	pthread_exit(NULL);
}


static int init_stats(int size) {
	stats = malloc(size * sizeof(t_pvd_stats*));
	for (int i = 0; i < size; ++i) {
		stats[i] = malloc(sizeof(t_pvd_stats));
		if (stats[i] == NULL) {
			pthread_mutex_lock(&mutex_print);
			fprintf(stderr, "Unable to allocate memory for the structure containing the PvD stats\n");
			fflush(stderr);
			pthread_mutex_unlock(&mutex_print);
			free_stats(stats, i);
			return EXIT_FAILURE;
		}
		stats[i]->info.name = NULL;
		stats[i]->info.addr = NULL;
		stats[i]->flow = NULL;
		for (int j = 0; j < 3; ++j) {
			stats[i]->tput[j].avg = 0;
			stats[i]->tput[j].min = 0;
			stats[i]->tput[j].max = 0;
			stats[i]->tput[j].nb = 0;
			stats[i]->rtt[j].avg = 0;
			stats[i]->rtt[j].min = 0;
			stats[i]->rtt[j].max = 0;
			stats[i]->rtt[j].nb = 0;
			stats[i]->acked_bytes[j] = 0;
		}
		stats[i]->rcvd_cnt = 0;
		stats[i]->snt_cnt = 0;
		pthread_mutex_init(&stats[i]->mutex, NULL);
		pthread_mutex_init(&stats[i]->mutex_acked, NULL);
	}
	return EXIT_SUCCESS;
}


static void *calculate_tput(void *args) {
	double curr_tput[3];
	t_pvd_max_min_avg *tput = NULL;

	while(1) {
		sleep(1);
		for (int i = 0; i < stats_size; ++i) {
			pthread_mutex_lock(&stats[i]->mutex_acked);
			// get number of acked bytes during last second (= current tput)
			for (int j = 0; j < 3; ++j) {
				curr_tput[j] = (double) stats[i]->acked_bytes[j] * 8 / 1000000; //tput in Mbps
				stats[i]->acked_bytes[j] = 0;
			}
			pthread_mutex_unlock(&stats[i]->mutex_acked);

			if (curr_tput[0] == 0)
				continue; // we ignore the times, when there is no packet transmission at all
			
			pthread_mutex_lock(&stats[i]->mutex);
			// update statistics values
			for (int j = 0; j < 3; ++j) {
				if (curr_tput[j] == 0)
					continue;
				tput = &stats[i]->tput[j];
				tput->min = (curr_tput[j] < tput->min || tput->min == 0) ? curr_tput[j] : tput->min;
				tput->max = (curr_tput[j] > tput->max) ? curr_tput[j] : tput->max;
				tput->avg = ((double)(tput->nb) * tput->avg + curr_tput[j]) / (double) (tput->nb+1);
				++tput->nb;
			}
			tput = NULL;
			pthread_mutex_unlock(&stats[i]->mutex);
		}
	}
	pthread_exit(NULL);
}


static void *sniff_packets(void *args) {
	t_pvd_stats *stats = (t_pvd_stats*) args;
	// As we're capturing on all the interfaces, the data link type will be LINKTYPE_LINUX_SLL.
	char *filter;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(NULL, BUFSIZ, 0, 0, errbuf);
	if (pcap == NULL) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		pthread_exit(NULL);
	}

	if (stats->info.addr[0] == NULL) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "There is no IPv6 address associated to the pvd %s\n"
			"Thus, no packets will be captured for this PvD.\n", stats->info.name);
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		pcap_close(pcap);
		pthread_exit(NULL);
	}

	// construct packet filter
	filter = construct_filter(stats->info.addr);
	printf("Packet filter: %s\n", filter);

	// compile our filter
	if (pcap_compile(pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN)) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "Error while compiling the packet filter for the PvD %s\n", stats->info.name);
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		pthread_exit(NULL);
	}

	// set the filter
	if (pcap_setfilter(pcap, &fp)) {
		pthread_mutex_lock(&mutex_print);
		fprintf(stderr, "Error while setting the packet filter for the PvD %s\n", stats->info.name);
		fflush(stderr);
		pthread_mutex_unlock(&mutex_print);
		pthread_exit(NULL);
	}

	free(filter);
	pcap_loop(pcap, -1, pcap_callback, (u_char*) stats);
	pcap_close(pcap);
	pthread_exit(NULL);
}


int main(int argc, char **argv) {
	pthread_t socket_thread;
	pthread_t tput_thread;
	pthread_attr_t thread_attr;

	// ==== collect PvD information ====
	t_pvd_list *pvd_list = get_pvd_list();
	if (pvd_list == NULL) {
		return EXIT_FAILURE;
	}
	stats_size = pvd_list->npvd;

	if (init_stats(stats_size))
		exit(0);

	// collect the PvD addresses
	for (int i = 0; i < stats_size; ++i) {
		stats[i]->info.name = strdup(pvd_list->pvdnames[i]);
		stats[i]->info.addr = get_pvd_addresses(pvd_list->pvdnames[i]);
		printf("IPv6 addresses corresponding to %s:\n", stats[i]->info.name);
		for (int j = 0; stats[i]->info.addr[j] != NULL; ++j) {
			printf("\t%s\n", stats[i]->info.addr[j]);
		}
		free(pvd_list->pvdnames[i]);
	}
	free(pvd_list);

	/*
	//to be removed after testing
	stats_size = 2;
	if (init_stats(stats_size))
		exit(0);
	stats[0]->info.name = strdup("video.mpvd.io.");
	stats[0]->info.addr = calloc(2, sizeof(char *));
	stats[0]->info.addr[0] = "fe80::cba3:7abd:be2e:9691";
	stats[1]->info.name = strdup("test1.example.com.");
	stats[1]->info.addr = calloc(3, sizeof(char *));
	stats[1]->info.addr[0] = "2a02:2788:b4:222:d4b6:3191:8a44:51a6";
	stats[1]->info.addr[1] = "2a02:2788:b4:222:cdf8:e989:b423:5443";
	*/

	// ==== Packet capturing ====
	pthread_t stats_thread[stats_size];

	// Thread handling communication with other applications using local UNIX sockets	
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&socket_thread, &thread_attr, socket_communication, NULL)) {
		fprintf(stderr, "Unable to create thread handling socket communication\n");
		exit(EXIT_FAILURE);
	}
	pthread_attr_destroy(&thread_attr);

	// Threads sniffing network packets
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
	for (int i = 0; i < stats_size; ++i) {
		if (pthread_create(&stats_thread[i], &thread_attr, sniff_packets, (void*) stats[i])) {
			pthread_mutex_lock(&mutex_print);
			fprintf(stderr, "Unable to create thread sniffing packets for PvD %s\n", stats[i]->info.name);
			fflush(stderr);
			pthread_mutex_unlock(&mutex_print);
		}
	}
	pthread_attr_destroy(&thread_attr);

	// Thread calculating throughput each second
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tput_thread, &thread_attr, calculate_tput, NULL)) {
		pthread_mutex_lock(&mutex_print);
			fprintf(stderr, "Unable to create thread calculating throughput\n");
			fflush(stderr);
			pthread_mutex_unlock(&mutex_print);
	}
	pthread_attr_destroy(&thread_attr);

	for (int i = 0; i < stats_size; ++i) {
		if (pthread_join(stats_thread[i], NULL)) {
			fprintf(stderr, "Error while joining packet sniffing threads\n");
			fflush(stderr);
			exit(EXIT_FAILURE);
		}
	}
	
	free_stats(stats, stats_size);
	fprintf(stderr, "Unable to sniff packets for any PvD.\nStopping\n");

	return EXIT_SUCCESS;
}