CFLAGS=-std=gnu99 -lpcap

all: 
	gcc ${CFLAGS} ipk-sniffer.c -o ipk-sniffer -lpcap