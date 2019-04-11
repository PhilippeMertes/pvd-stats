#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json-handler.h"

/*
int json_handler_print_value(FILE *stream, json_object *jobj) {
	enum json_type type = json_object_get_type(obj);

	switch (type) {
		case json_type_boolean:

	}
}
*/

char **json_handler_parse_string_array(const char *json_str) {
	json_object *jobj = json_tokener_parse(json_str);
	if (jobj == NULL) {
		fprintf(stderr, "json-handler error: unable to parse the string: %s\n", json_str);
		json_object_put(jobj);
		return NULL;
	}

	// check if the object really corresponds to an array
	if (!json_object_is_type(jobj, json_type_array)) {
		fprintf(stderr, "json_handler_parse_string_array error: the input string doesn't represent an array: %s\n", 
				json_str);
		json_object_put(jobj);
		return NULL;
	}

	// create and allocate return array
	int arr_len = json_object_array_length(jobj);
	char **elems = calloc(arr_len+1, sizeof(char*));
	if (elems == NULL) {
		fprintf(stderr, "json_handler_parse_string_array error: unable to allocate memory for return array\n");
		json_object_put(jobj);
		return NULL;
	}

	// walk through the elements of the array
	json_object *jelem;
	enum json_type type = json_type_null;
	for (int i = 0; i < arr_len; ++i) {
		jelem = json_object_array_get_idx(jobj, i);
		type = json_object_get_type(jelem);
		// check if array only contains strings
		if (type != json_type_string) {
			fprintf(stderr, "json_handler_parse_string_array error: element \"%s\" of array \"%s\" doesn't correspond to a string\n",
					json_object_to_json_string(jelem), json_object_to_json_string(jobj));
			for (int j = 0; j < i; ++j)
				free(elems[j]);
			free(elems);
			json_object_put(jobj);
			return NULL;
		} else {
			elems[i] = strdup(json_object_get_string(jelem));
		}
	}

	json_object_put(jobj);
	return elems;
}


char **json_handler_parse_addr_array(const char *json_str) {
	json_object *jobj = json_tokener_parse(json_str);
	if (jobj == NULL) {
		fprintf(stderr, "json-handler error: unable to parse the string: %s\n", json_str);
		json_object_put(jobj);
		return NULL;
	}

	// check if the object really corresponds to an array
	if (!json_object_is_type(jobj, json_type_array)) {
		fprintf(stderr, "json_handler_parse_string_array error: the input string doesn't represent an array: %s\n", 
				json_str);
		json_object_put(jobj);
		return NULL;
	}

	// create and allocate return array
	int arr_len = json_object_array_length(jobj);
	char **addr = calloc(arr_len+1, sizeof(char*));
	if (addr == NULL) {
		fprintf(stderr, "json_handler_parse_string_array error: unable to allocate memory for return array\n");
		json_object_put(jobj);
		return NULL;
	}
	
	// walk through the elements of the array
	json_object *jelem;
	enum json_type type = json_type_null;
	for (int i = 0; i < arr_len; ++i) {
		jelem = json_object_array_get_idx(jobj, i);
		type = json_object_get_type(jelem);
		if (type == json_type_null) {
			printf("No addresses are defined for the PvD\n");
			json_object_put(jobj);
			return NULL;
		}
		json_object *jaddr = NULL;
		if (json_object_object_get_ex(jelem, "address", &jaddr)) {
			addr[i] = strdup(json_object_get_string(jaddr));
		}
	}

	json_object_put(jobj);
	return addr;
}


char *json_handler_all_stats() {
	json_object *json = json_object_new_object();
	return NULL;
}

char *json_handler_rtt(t_pvd_stats **pvd_stats, const char *pvdname, int stats_size) {
	// ==== find stats corresponding to specified PvD =====
	t_pvd_stats *stats = NULL;
	char *json_str = NULL;
	for (int i = 0; i < stats_size; ++i) {
		if (strcmp(pvd_stats[i]->info.name, pvdname) == 0)
			stats = pvd_stats[i];
	}
	if (stats == NULL)
		return "No statistics found for the given PvD";


	// ==== create json ====
	json_object *json = json_object_new_object();

	// download
	json_object *jstat = json_object_new_object();
	json_object_object_add(jstat, "min", json_object_new_double(stats->rtt_dwn.min));
	json_object_object_add(jstat, "max", json_object_new_double(stats->rtt_dwn.max));
	json_object_object_add(jstat, "avg", json_object_new_double(stats->rtt_dwn.avg));
	json_object_object_add(json, "download", jstat);

	// upload
	jstat = json_object_new_object();
	json_object_object_add(jstat, "min", json_object_new_double(stats->rtt_up.min));
	json_object_object_add(jstat, "max", json_object_new_double(stats->rtt_up.max));
	json_object_object_add(jstat, "avg", json_object_new_double(stats->rtt_up.avg));
	json_object_object_add(json, "upload", jstat);

	// general stats
	jstat = json_object_new_object();
	json_object_object_add(jstat, "min", json_object_new_double(stats->rtt.min));
	json_object_object_add(jstat, "max", json_object_new_double(stats->rtt.max));
	json_object_object_add(jstat, "avg", json_object_new_double(stats->rtt.avg));
	json_object_object_add(json, "general", jstat);

	// create the string to return
	json_str = strdup(json_object_to_json_string(json));
	json_object_put(jstat);
	json_object_put(json);
	return json_str;
}

char *json_handler_tput() {
	return NULL;
}