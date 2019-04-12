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