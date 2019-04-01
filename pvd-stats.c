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

#include "json-handler.h"

#define PVDD_PORT 10101
#define SLL_LEN 16

typedef struct pvd_info {
	char *name;
	char **addr;
} t_pvd_info;

typedef struct pvd_throughput {
	unsigned int avg;
	unsigned int lst;
	long lst_ts;
	long ref_ts;
} t_pvd_throughput;

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
	}
}

/*
void recalculate_throughput(t_pvd_throughput *tput, long ts, int len) {
	// if it is the first packet arriving
	if (tput->lst_ts < 0) {
		tput->ref_ts = ts;
		tput->avg = len;
		tput->lst = len;
	}
	// if packets arrive at the same time
	else if(tput->lst_ts == ts) {
		tput->lst += len;
	}
	tput->lst_ts = ts;
}
*/

struct linux_sll {
	u_int16_t packet_type;
	u_int16_t arphrd_type;
	u_int16_t addr_len;
	unsigned char addr[8];
	u_int16_t protocol;
};

/*
u_int16_t get_ip_protocol_type(const u_char *packet) {
	struct linux_sll *sll = (struct linux_sll *) packet;
	printf("packet type: %d\n", ntohs(sll->packet_type));
	//printf("arphrd_type: %d\n", ntohs(sll->arphrd_type));
	return ntohs(sll->protocol);
}
*/


void pcap_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	t_pvd_stats *stats = (t_pvd_stats *) args;

	//printf("packet %d: ts = %ld, len = %d\n", stats->nb_packets++, pkthdr->ts.tv_sec, pkthdr->len);
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
	stats[0].info = malloc(sizeof(t_pvd_info));
	stats[0].info->addr = calloc(2, sizeof(char *));
	stats[0].info->addr[0] = "2a02:a03f:4208:4900:c1f6:d20d:1526:44be";

	for (int i = 0; i < stats_size; ++i) {
		// As we're capturing on all the interfaces, the data link type will be LINKTYPE_LINUX_SLL.
		stats[i].pcap = pcap_open_live(NULL, BUFSIZ, 0, 0, errbuf);
		if (stats[i].pcap == NULL) {
			fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
			exit(2);
		}
		printf("Datalink type: %d\n", pcap_datalink(stats[i].pcap));
		if (pcap_datalink(stats[i].pcap) == DLT_LINUX_SLL)
			printf("LINUX_SLL\n");

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

		// initialize statistics values
		stats[i].tput = malloc(sizeof(t_pvd_throughput));
		if (stats[i].tput == NULL) {
			fprintf(stderr, "Unable to allocate memory for the throughput of PvD: %s\n",
				stats[i].info->name);
			exit(EXIT_FAILURE);
		}
		stats[i].tput->lst_ts = -1;
		stats[i].tput->lst = 0;
		stats[i].tput->avg = 0;
		stats[i].rcvd_cnt = 0;
		stats[i].snt_cnt = 0;

		pcap_loop(stats[i].pcap, -1, pcap_callback, (u_char*) &stats[i]);

		free(filter);
	}

	free_stats(stats, stats_size);

	return EXIT_SUCCESS;
}