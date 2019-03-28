#ifndef JSON_HANDLER_H
#define JSON_HANDLER_H

#include <json-c/json.h>

//int json_handler_print_value(FILE *stream, json_object *jobj);
char **json_handler_parse_string_array(const char *json_str);
char **json_handler_parse_addr_array(const char *json_str);

#endif //JSON_HANDLER_H