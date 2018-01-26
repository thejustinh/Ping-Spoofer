# Example makefile for CPE465 program 1

CC = gcc
CFLAGS = -g -Wall #-Werror

all:  ping_spoof

ping_spoof: ping_spoof.c
	$(CC) $(CFLAGS) -o ping_spoof ping_spoof.c ping_spoof.h checksum.c smartalloc.c smartalloc.h -lpcap 

clean:
	rm -f ping_spoof
