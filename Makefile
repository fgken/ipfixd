PROGRAM=ipfixd
SRCS=*.c
CFLAGS= -g -O0 -std=gnu99
LDFLAGS= -lpcap

CC= gcc

all:
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SRCS) $(LDFLAGS)
