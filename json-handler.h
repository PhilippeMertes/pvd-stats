#ifndef JSON_HANDLER_H
#define JSON_HANDLER_H

#include <json-c/json.h>

#include "stats.h"

//int json_handler_print_value(FILE *stream, json_object *jobj);
char **json_handler_parse_string_array(const char *json_str);

char **json_handler_parse_addr_array(const char *json_str);

char *json_handler_all_stats();

char *json_handler_rtt(t_pvd_stats **pvd_stats, const char *pvdname, int stats_size);

char *json_handler_tput();

#endif //JSON_HANDLER_H