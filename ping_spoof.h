/*******************************
 * CPE 465 - Program 1 - ping_spoof.h
 * Winter 2018
 *
 * @author Justin Herrera
 ******************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>


#include <net/if.h>



#include "checksum.h"

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHERNET_HDR_SIZE 14
#define IP_MIN_HDR_SIZE 20
#define TCP_HDR_SIZE 20
#define TYPE_ARP 1
#define TYPE_IP 2
#define OP_REPLY 0x0002

#define INTERFACE "eth0"

#define HTTP_PORT 80
#define TELNET_PORT 23
#define FTP_PORT 20
#define POP3_PORT 110
#define SMTP_PORT 25
#define DNS_PORT 53

#define REQUEST 0x01

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define ACK 0x10
#define LOOP -1

/* IP Address String*/
char ip[16];
char * dev = NULL;
uint8_t mac[MAC_ADDR_LEN];

/* Ethernet Header */
struct ethernet_header {
   uint8_t dest[MAC_ADDR_LEN];
   uint8_t src[MAC_ADDR_LEN];
   uint16_t type;
} __attribute__((packed));

/* IP Header */
struct ip_header {
   uint8_t ver_hdr_len;
   uint8_t diffserv_ecn;
   uint16_t tot_len;
   uint16_t identification;
   uint16_t fragment;
   uint8_t ttl;
   uint8_t protocol;
   uint16_t checksum;
   struct in_addr source_addr;
   struct in_addr dest_addr;
} __attribute__((packed));

/* TCP Header */
struct tcp_header {
   uint16_t source_port;
   uint16_t dest_port;
   uint32_t seq;
   uint32_t ack_num;
   uint8_t hdr_len;
   uint8_t flags;
   uint16_t window_size;
   uint16_t checksum;
   uint16_t urgent;
} __attribute__((packed));

/* TCP Pseudoheader */
struct tcp_pseudo {
   struct in_addr source_addr;
   struct in_addr dest_addr;
   uint8_t reserved;
   uint8_t protocol;
   uint16_t length;
} __attribute__((packed));

/* UDP Header */
struct udp_header {
   uint16_t source_port;
   uint16_t dest_port;
   uint16_t length;
   uint16_t checksum;
} __attribute__((packed));

/* ICMP Header */
struct icmp_header {
   uint8_t type;
   uint8_t code;
   uint16_t checksum;
   uint16_t identifier;
   uint16_t seq_num;
} __attribute__((packed));

/* Arp Header */
struct arp_header {
   uint16_t hardware_type;
   uint16_t protocol_type;
   uint8_t hardware_size;
   uint8_t protocol_size;
   uint16_t opcode; /* request (1) or reply */
   uint8_t sender_mac_addr[MAC_ADDR_LEN];
   struct in_addr sender_ip_addr;
   uint8_t target_mac_addr[MAC_ADDR_LEN];
   struct in_addr target_ip_addr;
} __attribute__((packed));
