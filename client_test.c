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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define SOCKET_FILE "/tmp/pvd-stats.uds"

int main(int argc, char ** argv) {
	int create_socket;

	struct sockaddr_un addr;
	char msg[2048];
	ssize_t size;

	printf("Message to send: ");
	fgets(msg, 256, stdin);
	printf("msg: %s\n", msg);

	if ((create_socket = socket(PF_LOCAL, SOCK_STREAM, 0)) > 0)
		printf("Socket successfully created\n");

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, SOCKET_FILE);

	if (connect(create_socket, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
		printf("Connected successfully to pvd-stats\n");
		send(create_socket, msg, strlen(msg), 0);
	}
	else {
		fprintf(stderr, "Connection error: %s\n", strerror(errno));
	}

	size = recv(create_socket, msg, 2048, 0);
	printf("Answer: %s\n", msg);

	return EXIT_SUCCESS;
}