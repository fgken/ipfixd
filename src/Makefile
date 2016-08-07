PROGRAM=ipfixd
SRCS=*.c murmur3/murmur3.c
CFLAGS= -Imurmur3 -g -O0 -std=gnu99 -pthread
LDFLAGS= -lpcap

CC= gcc

all:
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SRCS) $(LDFLAGS)
