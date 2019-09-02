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

#ifndef JSON_HANDLER_H
#define JSON_HANDLER_H

#include <json-c/json.h>

#include "stats.h"

/**
 * Parses a JSON string corresponding to an array of string values.
 *
 * @param json_str string representation of the JSON array
 * @return array of the string elements
 */
char **json_handler_parse_string_array(const char *json_str);

/**
 * Parses a JSON string representing an array of IPv6 addresses.
 *
 * @param json_str string representation of the JSON array
 * @return an array of IPv6 addresses (strings)
 */
char **json_handler_parse_addr_array(const char *json_str);

/**
 * Constructs a JSON object holding all statistics for all PvDs.
 *
 * @param stats #t_pvd_stats structure holding the statistics
 * @param stats_size number of PvDs
 * @return JSON object
 */
json_object *json_handler_all_stats(t_pvd_stats **stats, const int stats_size);

/**
 * Constructs a JSON object holding Round-Trip Time statistics for all PvDs.
 *
 * @param stats #t_pvd_stats structure holding the statistics
 * @param stats_size number of PvDs
 * @return JSON object
 */
json_object *json_handler_rtt_stats(t_pvd_stats **stats, const int stats_size);

/**
 * Constructs a JSON object holding throughput statistics for all PvDs.
 *
 * @param stats #t_pvd_stats structure holding the statistics
 * @param stats_size number of PvDs
 * @return JSON object
 */
json_object *json_handler_tput_stats(t_pvd_stats **stats, const int stats_size);

/**
 * Constructs a JSON object holding all statistics for one PvD.
 *
 * @param stats statistics corresponding to one PvD
 * @return JSON object
 */
json_object *json_handler_all_stats_one_pvd(t_pvd_stats *stats);

/**
 * Constructs a JSON object holding Round-Trip Time statistics for one PvD.
 *
 * @param stats statistics corresponding to one PvD
 * @return JSON object
 */
json_object *json_handler_rtt_stats_one_pvd(t_pvd_stats *stats);

/**
 * Constructs a JSON object holding throughput statistics for one PvD.
 *
 * @param stats statistics corresponding to one PvD
 * @return JSON object
 */
json_object *json_handler_tput_stats_one_pvd(t_pvd_stats *stats);

#endif //JSON_HANDLER_H
