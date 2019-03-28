#include <libpvd.h>
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <json-c/json.h>
#include <string.h>

#include "json-handler.h"

#define PVDD_PORT 10101

typedef struct pvd_info {
	char *name;
	char **addresses;
} t_pvd_info;

typedef struct pvd_stats {
	t_pvd_info *info;
	int nb_packets;
} t_pvd_stats;


t_pvd_list *get_pvd_list() {
	t_pvd_connection *conn = pvd_connect(PVDD_PORT);
	t_pvd_list *list = malloc(sizeof(t_pvd_list));

	if(pvd_get_pvd_list_sync(conn, list))
		fprintf(stderr, "get_pvd_list: Error while retrieving PvDs list.\n"
			"Make sure that pvdd is running on port %d\n", PVDD_PORT);

	pvd_disconnect(conn);
	return list;
}

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


void free_stats(t_pvd_stats *stats, int size) {
	t_pvd_info *info = NULL;
	for (int i = 0; i < size; ++i) {
		info = stats[i].info;
		free(info->name);
		for (int j = 0; info->addresses[j] != NULL; ++j) {
			free(info->addresses[j]);
		}
		free(info);
	}
}


int main(int argc, char **argv) {
	// collect PvD information
	t_pvd_list *pvd_list = get_pvd_list();
	char **addresses = NULL;
	int stats_size = pvd_list->npvd;

	t_pvd_stats stats[stats_size];

	for (int i = 0; i < stats_size; ++i) {
		stats[i].info = malloc(sizeof(t_pvd_info));
		stats[i].info->name = strdup(pvd_list->pvdnames[i]);
		addresses = get_pvd_addresses(pvd_list->pvdnames[i]);
		printf("IPv6 addresses corresponding to %s:\n", pvd_list->pvdnames[i]);
		for (int j = 0; addresses[j] != NULL; ++j) {
			printf("\t%s\n", addresses[j]);
			free(addresses[j]);
		}
		free(pvd_list->pvdnames[i]);
	}

	for (int i = 0; i < stats_size; ++i) {
		printf("%s\n", stats[i].info->name);
	}

	free_stats(stats, stats_size);
	free(addresses);
	free(pvd_list);

	/*
	pcap_t *session;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char *filter;

	// start packet capturing session on all interfaces
	session = pcap_open_live(NULL, BUFSIZ, 0, 0, errbuf);
	if (session == NULL) {
		fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
		exit(2);
	}

	// construct packet filter
	//sprintf(filter, "dst or src host %s\n", );

	// compile our filter
	if (pcap_compile(session, &fp, "dst or src host 8.8.8.8", 0, PCAP_NETMASK_UNKNOWN)) {
		perror("Error while compiling the packet filter\n");
		exit(2);
	}

	// set the filter
	if (pcap_setfilter(session, &fp)) {
		perror("Error while setting the packet filter\n");
		exit(2);
	}

	free(pvd_list);
	*/

	return EXIT_SUCCESS;
}