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


static json_object *create_json_for_all_pvds(t_pvd_stats **stats, const int stats_size, json_object* (*stats_of_pvd)(t_pvd_stats*)) {
	json_object *json = json_object_new_object();
	for (int i = 0; i < stats_size; ++i)
		json_object_object_add(json, stats[i]->info.name, (*stats_of_pvd) (stats[i]));
	return json;
}


json_object *json_handler_all_stats(t_pvd_stats **stats, const int stats_size) {
	return create_json_for_all_pvds(stats, stats_size, json_handler_all_stats_one_pvd);
}


json_object *json_handler_rtt_stats(t_pvd_stats **stats, const int stats_size) {
	return create_json_for_all_pvds(stats, stats_size, json_handler_rtt_stats_one_pvd);
}


json_object *json_handler_tput_stats(t_pvd_stats **stats, const int stats_size) {
	return create_json_for_all_pvds(stats, stats_size, json_handler_tput_stats_one_pvd);
}


json_object *json_handler_all_stats_one_pvd(t_pvd_stats *stats) {
	json_object *json = json_object_new_object();
	json_object_object_add(json, "rtt", json_handler_rtt_stats_one_pvd(stats));
	json_object_object_add(json, "tput", json_handler_tput_stats_one_pvd(stats));
	return json;
}


json_object *json_handler_rtt_stats_one_pvd(t_pvd_stats *stats) {
	json_object *json = json_object_new_object();
	json_object *jstat = NULL;

	// create a json object for general, upload and download rtt and add them together
	for (int i = 0; i < 3; ++i) {
		jstat = json_object_new_object();
		json_object_object_add(jstat, "min", json_object_new_double(stats->rtt[i].min));
		json_object_object_add(jstat, "max", json_object_new_double(stats->rtt[i].max));
		json_object_object_add(jstat, "avg", json_object_new_double(stats->rtt[i].avg));
		if (i == 0)
			json_object_object_add(json, "general", jstat);
		else
			json_object_object_add(json, (i == 1) ? "upload" : "download", jstat);
	}

	return json;
}


json_object *json_handler_tput_stats_one_pvd(t_pvd_stats *stats) {
	json_object *json = json_object_new_object();
	json_object *jstat = NULL;

	// create a json object for general, upload and download tput and add them together
	for (int i = 0; i < 3; ++i) {
		jstat = json_object_new_object();
		json_object_object_add(jstat, "min", json_object_new_double(stats->tput[i].min));
		json_object_object_add(jstat, "max", json_object_new_double(stats->tput[i].max));
		json_object_object_add(jstat, "avg", json_object_new_double(stats->tput[i].avg));
		if (i == 0)
			json_object_object_add(json, "general", jstat);
		else
			json_object_object_add(json, (i == 1) ? "upload" : "download", jstat);
	}

	return json;
}