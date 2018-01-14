# Example makefile for CPE465 program 1

CC = gcc
CFLAGS = -g -Wall -Werror

all:  ping_spoof

ping_spoof: ping_spoof.c
	$(CC) $(CFLAGS) ping_spoof.c ping_spoof.h checksum.c  -lpcap 

clean:
	rm -f ping_spoof
