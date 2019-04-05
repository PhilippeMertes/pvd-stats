CC = gcc
CFLAGS = -Wall -g -O2
LIBS = -lpcap -ljson-c

.PHONY: all pvd-stats

all : pvd-stats

pvd-stats:
	$(CC) pvd-stats.c json-handler.c stats.c -o pvd-stats $(CFLAGS) $(LIBS)
	
clean :
	/bin/rm -f pvd-stats
