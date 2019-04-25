CC = gcc
CFLAGS = -Wall -g -O2
LIBS = -lpcap -ljson-c -lpthread -lpvd

.PHONY: all pvd-stats client-test

all : pvd-stats client-test

pvd-stats:
	$(CC) pvd-stats.c json-handler.c stats.c -o pvd-stats $(CFLAGS) $(LIBS)

client-test:
	$(CC) client_test.c -o client-test $(CFLAGS) $(LIBS)
	
clean :
	/bin/rm -f pvd-stats client-test
