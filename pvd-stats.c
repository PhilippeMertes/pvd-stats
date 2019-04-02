//#include <libpvd.h>
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
//#include <netinet/if_ether.h>
#include <json-c/json.h>
#include <string.h>
//#include <unistd.h>
//#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
//#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <math.h>

#include "json-handler.h"

#define PVDD_PORT 10101
#define LEN_SLL 16
#define LEN_IPV6 40
#define TIMEOUT 10

typedef struct pvd_info {
	char *name;
	char **addr;
} t_pvd_info;

typedef struct pvd_rtt {
	double avg;
	double max;
	double min;
	unsigned int nb;
} t_pvd_rtt;

typedef struct pvd_throughput {
	double avg;
	double max;
	double min;
	unsigned int nb;
} t_pvd_throughput;

typedef struct pvd_tcp_session {
	u_int8_t src_ip[16];
	u_int8_t dst_ip[16];
	u_int16_t src_port;
	u_int16_t dst_port;
	struct timeval *ts;
	struct pvd_tcp_session *next;
} t_pvd_tcp_session;

typedef struct pvd_tcp {
	t_pvd_throughput *tput;
	unsigned int rtt;
} t_pvd_tcp;

typedef struct pvd_stats {
	t_pvd_info *info;
	pcap_t *pcap;
	unsigned int rcvd_cnt;
	unsigned int snt_cnt;
	t_pvd_throughput *tput;
	t_pvd_rtt *rtt;
	t_pvd_tcp_session *tcp_sess;
} t_pvd_stats;

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

void free_stats(t_pvd_stats *stats, int size) {
	t_pvd_info *info = NULL;
	for (int i = 0; i < size; ++i) {
		info = stats[i].info;
		free(info->name);
		for (int j = 0; info->addr[j] != NULL; ++j) {
			free(info->addr[j]);
		}
		free(info);
		pcap_close(stats[i].pcap);
		free(stats[i].tput);
		free(stats[i].rtt);
		t_pvd_tcp_session *sess = stats[i].tcp_sess;
		t_pvd_tcp_session *next_sess;
		while(sess != NULL) {
			next_sess = sess->next;
			free(sess->ts);
			free(sess);
			sess = next_sess;
		}
	}
}


int init_stats(t_pvd_stats *stats, int size) {
	for (int i = 0; i < size; ++i) {
		stats[i].info = malloc(sizeof(t_pvd_info));
		stats[i].tput = malloc(sizeof(t_pvd_throughput));
		stats[i].rtt = malloc(sizeof(t_pvd_rtt));
		stats[i].tcp_sess = NULL;
		if (stats[i].info == NULL || stats[i].tput == NULL || stats[i].rtt == NULL) {
			fprintf(stderr, "Unable to allocate memory for the structure containing the PvD stats\n");
			free_stats(stats, i);
			return EXIT_FAILURE;
		}
		stats[i].tput->avg = 0;
		stats[i].tput->min = 0;
		stats[i].tput->max = 0;
		stats[i].tput->nb = 0;
		stats[i].rcvd_cnt = 0;
		stats[i].snt_cnt = 0;
	}
	return EXIT_SUCCESS;
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

int add_tcp_session(t_pvd_stats *stats, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port, const struct timeval ts) {
	// if there is no element in the linked list
	if (stats->tcp_sess == NULL) {
		stats->tcp_sess = malloc(sizeof(t_pvd_tcp_session));
		if (stats->tcp_sess == NULL) {
			fprintf(stderr, "Unable to allocate memory to store the session\n");
			return EXIT_FAILURE;
		}
		stats->tcp_sess->ts = malloc(sizeof(struct timeval));
		if (stats->tcp_sess->ts == NULL) {
			fprintf(stderr, "Unable to allocate memory to store the session\n");
			return EXIT_FAILURE;
		}
		memcpy(stats->tcp_sess->src_ip, src_ip, 16);
		memcpy(stats->tcp_sess->dst_ip, dst_ip, 16);
		stats->tcp_sess->src_port = src_port;
		stats->tcp_sess->dst_port = dst_port;
		stats->tcp_sess->ts->tv_sec = ts.tv_sec;
		stats->tcp_sess->ts->tv_usec = ts.tv_usec;
		stats->tcp_sess->next = NULL;
	}

	t_pvd_tcp_session *sess = stats->tcp_sess;
	t_pvd_tcp_session *prev_sess = NULL;
	/* get to the last element of the linked list,
	   while deleting elements with a timestamp older than TIMEOUT */
	while (sess->next != NULL) {
		if (ts.tv_sec - sess->ts->tv_sec > TIMEOUT) {
			// the first element is outdated
			if (prev_sess == NULL) {
				stats->tcp_sess = sess->next;
				free(sess->ts);
				free(sess);
				sess = stats->tcp_sess;
			} // an element in the middle
			else {
				prev_sess->next = sess->next;
				free(sess->ts);
				free(sess);
				sess = prev_sess->next;
			}
		} // the element is up-to-date
		else {
			prev_sess = sess;
			sess = sess->next;
		}
	}

	// allocate memory
	sess->next = malloc(sizeof(t_pvd_tcp_session));
	if (sess->next == NULL) {
		fprintf(stderr, "Unable to allocate memory to store the session\n");
		return EXIT_FAILURE;
	}
	sess = sess->next;
	sess->ts = malloc(sizeof(struct timeval));
	if (sess->ts == NULL) {
		fprintf(stderr, "Unable to allocate memory to store the session\n");
		return EXIT_FAILURE;
	}

	// add values to the new element
	memcpy(sess->src_ip, src_ip, 16);
	memcpy(sess->dst_ip, dst_ip, 16);
	sess->src_port = src_port;
	sess->dst_port = dst_port;
	sess->ts->tv_sec = ts.tv_sec;
	sess->ts->tv_usec = ts.tv_usec;
	sess->next = NULL;

	return EXIT_SUCCESS;
}


t_pvd_tcp_session *find_tcp_session(t_pvd_tcp_session *sessions, const u_int8_t src_ip[16], const u_int8_t dst_ip[16],
	const u_int16_t src_port, const u_int16_t dst_port) {
	t_pvd_tcp_session *sess = sessions;
	printf("[");

	while(sess != NULL) {	
		printf("(");
		print_ip6_addr(sess->src_ip);
		printf(", ");
		print_ip6_addr(sess->dst_ip);
		printf(", %d, %d, %ld, %ld) ", sess->src_port, sess->dst_port, sess->ts->tv_sec, sess->ts->tv_usec);
		if (!memcmp(sess->src_ip, src_ip, 16) && !memcmp(sess->dst_ip, dst_ip, 16)
			&& sess->src_port == src_port && sess->dst_port == dst_port)
			break;
		sess = sess->next;
	}
	printf("]\n");
	return sess;
}

void update_throughput_rtt(t_pvd_stats *stats, t_pvd_tcp_session *sess, struct timeval ts, u_int16_t win) {
	double curr_rtt = (ts.tv_sec + ts.tv_usec * pow(10, -6)) - (sess->ts->tv_sec + sess->ts->tv_usec * pow(10, -6));
	printf("curr_rtt: %f\n", curr_rtt);
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
		printf("SYN: %d\n", tcp->syn);
		printf("ACK: %d\n", tcp->ack);
		printf("FIN: %d\n", tcp->fin);
		t_pvd_tcp_session *sess;
		
		// packet sent by the client
		if (!rcvd) {
			sess = find_tcp_session(stats->tcp_sess, ip->ip6_src.s6_addr, ip->ip6_dst.s6_addr, ntohs(tcp->source), ntohs(tcp->dest));
			if (!sess)
				add_tcp_session(stats, ip->ip6_src.s6_addr, ip->ip6_dst.s6_addr, ntohs(tcp->source), ntohs(tcp->dest), pkthdr->ts);
			else {
				// update timestamp of the session
				printf("Known session. Timestamp gets updated\n");
				sess->ts->tv_sec = pkthdr->ts.tv_sec;
				sess->ts->tv_usec = pkthdr->ts.tv_usec;
			}
		}
		// packet received
		else {
			sess = find_tcp_session(stats->tcp_sess, ip->ip6_dst.s6_addr, ip->ip6_src.s6_addr, ntohs(tcp->dest), ntohs(tcp->source));
			if (sess && !tcp->syn)
				update_throughput_rtt(stats, sess, pkthdr->ts, tcp->window);
		}
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
	stats[0].info->addr[0] = "2a02:a03f:434a:4300:c1f6:d20d:1526:44be";

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