PROGRAM=ipfixd
SRCS=*.c
CFLAGS= -g -O0
LDFLAGS= -l pcap

CC= gcc

all:
	$(CC) -o $(PROGRAM) $(CFLAGS) $(LDFLAGS) $(SRCS)
