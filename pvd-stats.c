//#include <libpvd.h>
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

#include "json-handler.h"
#include "stats.h"

#define PVDD_PORT 10101
#define LEN_SLL 16
#define LEN_IPV6 40

/*
t_pvd_list *get_pvd_list() {
	t_pvd_connection *conn = pvd_connect(PVDD_PORT);
	t_pvd_list *list = malloc(sizeof(t_pvd_list));

	if(pvd_get_pvd_list_sync(conn, list))
		fprintf(stderr, "get_pvd_list: Error while retrieving PvDs list.\n"
			"Make sure that pvdd is running on port %d\n", PVDD_PORT);

	pvd_disconnect(conn);
	return list;
}
*/
/*
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
*/

/*
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
*/


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

	printf("ts_sec = %ld, ts_usec = %ld, len = %d\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->len);
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
	printf("src ip: ");
	print_ip6_addr(ip->ip6_src.s6_addr);
	printf("\n");
	printf("dst ip: ");
	print_ip6_addr(ip->ip6_dst.s6_addr);
	printf("\n");

	// check if packet contains some transport-layer payload
	if (ntohs(ip->ip6_plen) == 0)
		return;

	// ==== TCP transport-layer ====
	if (ip->ip6_nxt == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) &packet[LEN_SLL+LEN_IPV6];
		printf("source port: %d\n", ntohs(tcp->source));
		printf("dest port: %d\n", ntohs(tcp->dest));
		printf("window: %d\n", ntohs(tcp->window));
		printf("data offset: %d\n", tcp->doff);
		printf("SEQ: %u\n", ntohl(tcp->seq));
		printf("ACK_SEQ: %u\n", ntohl(tcp->ack_seq));
		printf("SYN: %d\n", tcp->syn);
		printf("ACK: %d\n", tcp->ack);
		printf("FIN: %d\n", tcp->fin);

		// we don't take TCP handshake flows into account
		if (tcp->syn)
			return;

		// find the flow to which we ack
		t_pvd_flow *flow = find_flow(stats->flow, ip->ip6_dst.s6_addr, ip->ip6_src.s6_addr,
			ntohs(tcp->dest), ntohs(tcp->source), ntohl(tcp->ack_seq));
		//print_flow(stats->flow);

		if (flow) {
			printf("Flow found. Calculating throughput and RTT\n");
			update_throughput_rtt(stats->tput, stats->rtt, flow, pkthdr->ts);
			// if we received the packet, then it is an ACK to an uploaded packet
			if (rcvd) {
				printf("UPLOAD\n");
				update_throughput_rtt(stats->tput_up, stats->rtt_up, flow, pkthdr->ts);
			}
			else {
				printf("DOWNLOAD\n");
				update_throughput_rtt(stats->tput_dwn, stats->rtt_dwn, flow, pkthdr->ts);
			}
			remove_flow(stats, flow);
		}

		// calculate expected ACK
		u_int32_t seq = ntohl(tcp->seq);
		u_int32_t ack = seq;
		ack += pkthdr->len - LEN_SLL - LEN_IPV6 - tcp->doff * 4; // TCP payload
		printf("Expected ack: %u\n", ack);
		// If the packet contains no payload, it doesn't need to be acked by the other side.
		// Thus, we don't need to keep track of it.
		if (seq != ack)
			add_flow(stats, ip->ip6_src.s6_addr, ip->ip6_dst.s6_addr, ntohs(tcp->source), ntohs(tcp->dest), seq, ack, pkthdr->ts);
	}
	printf("\n");
}


char *construct_filter(char **addr) {
	// detect filter length
	int filt_len = snprintf(NULL, 0, "dst or src host %s", addr[0]);
	for (int i = 1; addr[i] != NULL; ++i)
		filt_len += snprintf(NULL, 0, " or %s", addr[i]);
	if (filt_len < 0) {
		fprintf(stderr, "Error while constructing packet filter\n");
		return NULL;
	}
	// create filter
	char *filter = malloc(++filt_len * sizeof(char));
	int pos = sprintf(filter, "dst or src host %s", addr[0]);
	for (int i = 1; addr[i] != NULL; ++i)
		pos += sprintf(&filter[pos], " or %s", addr[i]);
	return filter;
}


int main(int argc, char **argv) {
	// ==== collect PvD information ====
	/*
	t_pvd_list *pvd_list = get_pvd_list();
	int stats_size = pvd_list->npvd;
	t_pvd_stats stats[stats_size];

	// collect the PvD addresses
	for (int i = 0; i < stats_size; ++i) {
		stats[i].info = malloc(sizeof(t_pvd_info));
		if (stats[i].info == NULL) {
			fprintf(stderr, "Unable to allocate memory to store PvD information\n");
			exit(EXIT_FAILURE);
		}
		stats[i].info->name = strdup(pvd_list->pvdnames[i]);
		stats[i].info->addr = get_pvd_addresses(pvd_list->pvdnames[i]);
		printf("IPv6 addresses corresponding to %s:\n", stats[i].info->name);
		for (int j = 0; stats[i].info->addr[j] != NULL; ++j) {
			printf("\t%s\n", stats[i].info->addr[j]);
		}
		free(pvd_list->pvdnames[i]);
	}
	free(pvd_list);
	*/


	// ==== Packet capturing ====
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char *filter;

	// to be removed afterwards
	int stats_size = 1;
	t_pvd_stats stats[stats_size];
	if (init_stats(stats, stats_size))
		exit(0);
	stats[0].info->addr = calloc(2, sizeof(char *));
	stats[0].info->addr[0] = "fdb7:ba30:d998:0:b408:7d00:8786:c9c9";

	for (int i = 0; i < stats_size; ++i) {
		// As we're capturing on all the interfaces, the data link type will be LINKTYPE_LINUX_SLL.
		stats[i].pcap = pcap_open_live(NULL, BUFSIZ, 0, 0, errbuf);
		if (stats[i].pcap == NULL) {
			fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
			exit(2);
		}

		if (stats[i].info->addr[0] == NULL) {
			printf("There is no address associated to the pvd %s\n", stats[i].info->name);
			continue;
		}

		// construct packet filter
		filter = construct_filter(stats[i].info->addr);
		printf("Packet filter: %s\n", filter);

		// compile our filter
		if (pcap_compile(stats[i].pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN)) {
			perror("Error while compiling the packet filter\n");
			exit(2);
		}

		// set the filter
		if (pcap_setfilter(stats[i].pcap, &fp)) {
			perror("Error while setting the packet filter\n");
			exit(2);
		}
		
		pcap_loop(stats[i].pcap, -1, pcap_callback, (u_char*) &stats[i]);

		free(filter);
	}

	free_stats(stats, stats_size);

	return EXIT_SUCCESS;
}