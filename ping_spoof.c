/************************************
 * CPE 465 - Program 1 - ping_spoof.c
 * Winter 2018
 *
 * @author Justin Herrera
 ***********************************/

#include "ping_spoof.h"
#include "smartalloc.h"
#include <signal.h>

pcap_t *handle; // Session handle

/******************************************************************************
  * A method to send the created packet through the device we are sniffing on.
  *
  * @param int type - used to determine if type is of ARP or IP
  * @param const u_char *pkt_data - packet data
  * @return 0 on success, -1 otherwise
  ****************************************************************************/
int sendPacket(uint8_t * packet, size_t packet_length) {

  struct ifreq ifidx;            // interface index
  struct sockaddr_ll dest_addr;  // target address
  int sd, i;                     // raw socket descriptor

  /* make a raw socket */
  if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
    perror("[-] Error! Cannot create raw socket");
    return -1;
  }

  /* Get the index of the interface to send on */
  strncpy(ifidx.ifr_name, dev, strlen(dev));          // set interface name
  if( ioctl(sd, SIOCGIFINDEX, &ifidx) < 0 ) {         // get interface index
    perror("[-] Error! Cannot get interface index");
    return -1;
  }

  dest_addr.sll_ifindex = ifidx.ifr_ifindex;           // interface index
  dest_addr.sll_halen   = ETH_ALEN;                    // address length

  for( i=0; i<6; ++i ) dest_addr.sll_addr[i] = mac[i]; // set target MAC address

  /* send spoofed packet (set routing flags to 0) */
  if(sendto(sd, packet, packet_length, 0, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr_ll)) < 0) {
    perror("[-] Error! Cannot send spoofed frame");
    return -1;
  } 

  return 0; // success!

}

/******************************************************************************
  * A method to determine if a packet's destination IP matches our spoofed IP.
  * Also checks for checksum correction.
  *
  * @param int type - used to determine if type is of ARP or IP
  * @param const u_char *pkt_data - packet data
  * @return 1 if valid, 0 otherwise
  ****************************************************************************/
int validPacket(int type, const u_char *packet) {

  struct arp_header *arp_hdr;
  struct ip_header *ip_hdr;
  struct icmp_header *icmp_hdr;
  int saved_checksum;
  u_char ip_buf[16];
  memset(ip_buf, 0, 16);

  // Extracting packet information
  if (type == TYPE_ARP) {

    // Define ARP header
    arp_hdr = (struct arp_header *)(packet + ETHERNET_HDR_SIZE);

    // copy target ip address into buffer to be printed
    memcpy(ip_buf, inet_ntoa(arp_hdr->target_ip_addr), 15);

    // Drop Packet if we received an arp reply (only respond to arp requests)
    if (ntohs(arp_hdr->opcode) != REQUEST) {
      return 0;
    }

  } else if (type == TYPE_IP) {

    // Define IP and ICMP header
    ip_hdr = (struct ip_header *)(packet + ETHERNET_HDR_SIZE);
    icmp_hdr = (struct icmp_header *)(packet + ETHERNET_HDR_SIZE + ((ip_hdr->ver_hdr_len & 0x0f) *4));

    // Drop packet if we received ICMP reply (only respond to echo requests)
    if (icmp_hdr->type != 0x08) {
      return 0;
    }

    // Copy target ip address into buffer to be printed
    memcpy(ip_buf, inet_ntoa(ip_hdr->dest_addr), 15);

    // Checksum Correction
    saved_checksum = ip_hdr->checksum;
    ip_hdr->checksum = 0;
    ip_hdr->checksum = in_cksum((unsigned short *)ip_hdr, (ip_hdr->ver_hdr_len & 0x0f) * 4);

    // If checksum is correct, return 0 and drop packet
    if (saved_checksum != (int)ip_hdr->checksum)
      return 0;

  } else {
    fprintf(stderr, "Invalid type field.");
    return 0;
  }

  // If packet's target IP is not spoofed IP, drop packet.
  if (strncmp((const char *)ip, (const char *)ip_buf, 15) != 0)
    return 0;

  return 1;

}

/******************************************************************************
 * This method constructs an ICMP packet.
 *
 * @param const u_char *packet - this is the received packet
 *****************************************************************************/
void constructSendICMP(const u_char *packet) {

  struct in_addr src_addr;
  struct in_addr dest_addr;
  const struct ethernet_header *ethernet_hdr;
  const struct ip_header *ip_hdr;
  const struct icmp_header *icmp_hdr;

  /* Data from received packet */
  ethernet_hdr = (struct ethernet_header *) packet;
  ip_hdr = (struct ip_header *) (packet + ETHERNET_HDR_SIZE);
  icmp_hdr = (struct icmp_header *) (packet + ETHERNET_HDR_SIZE + ((ip_hdr->ver_hdr_len&0x0f) * 4));
  int packet_size = ETHERNET_HDR_SIZE + ntohs(ip_hdr->tot_len);
  uint8_t new_packet[packet_size];
  memset(new_packet, 0, packet_size);

  /* New packet arguments */
  /* IP */
  uint16_t type = htons(ETHERTYPE_IP);
  uint8_t version_header = 0x45;
  uint8_t diffserv = 0x00;
  uint16_t total_length = ip_hdr->tot_len; /* new packet same length as recv'd */
  uint16_t id = htons(9999); /* random ID */
  uint16_t frag = 0x0000;
  uint8_t ttl = 0x40;
  uint8_t protocol = 0x01;
  uint16_t checksum = 0x0000;
  inet_aton(ip, &src_addr); /* convert string to in_addr_t */
  dest_addr = ip_hdr->source_addr;

  /* ICMP */
  uint8_t icmp_type = 0x0;
  uint8_t icmp_code = 0x0;
  uint16_t icmp_checksum = 0x0000;
  uint16_t icmp_id = icmp_hdr->identifier;
  uint16_t icmp_seq = icmp_hdr->seq_num;

  memcpy(new_packet, ethernet_hdr->src, MAC_ADDR_LEN); /* Ethernet fields */
  memcpy(new_packet + MAC_ADDR_LEN, mac, MAC_ADDR_LEN);
  memcpy(new_packet + (2 * MAC_ADDR_LEN), &type, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE, &version_header, 1); /* IP fields */
  memcpy(new_packet + ETHERNET_HDR_SIZE + 1, &diffserv, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 2, &total_length, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 4, &id, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 6, &frag, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 8, &ttl, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 9, &protocol, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 10, &checksum, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 12, &src_addr, 4);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 16, &dest_addr, 4);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 20, &icmp_type, 1); /* ICMP fields */
  memcpy(new_packet + ETHERNET_HDR_SIZE + 21, &icmp_code, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 22, &icmp_checksum, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 24, &icmp_id, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 26, &icmp_seq, 2);

  /* added payload copy */
  memcpy(new_packet + ETHERNET_HDR_SIZE + 28, packet + ETHERNET_HDR_SIZE + 28, 
         packet_size - (ETHERNET_HDR_SIZE + 28));

  /* Save IP Checksum */
  checksum = in_cksum((unsigned short *)(new_packet + ETHERNET_HDR_SIZE), 20);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 10, &checksum, 2);

  /* Save ICMP Checksum */
  icmp_checksum = in_cksum((unsigned short *)(new_packet + ETHERNET_HDR_SIZE + 20),
                    packet_size - ETHERNET_HDR_SIZE - IP_MIN_HDR_SIZE);

  memcpy(new_packet + ETHERNET_HDR_SIZE + 22, &icmp_checksum, 2);

  if ((sendPacket(new_packet, (size_t)packet_size)) != 0)
    fprintf(stderr, "Error sending ICMP packet\n");

}

/******************************************************************************
 * This method constructs and ARP packet.
 * 
 * @param const u_char *packet - this is the received packet
 *****************************************************************************/
void constructSendARP(const u_char *packet) {

  uint8_t new_packet[ETHERNET_HDR_SIZE + 28];
  const struct ethernet_header *ethernet_hdr;
  const struct arp_header *arp_hdr;
  struct in_addr src_addr;
  struct in_addr dest_addr;

  ethernet_hdr = (struct ethernet_header *) packet;
  arp_hdr = (struct arp_header *) (packet + ETHERNET_HDR_SIZE);

  uint16_t type = htons(ETHERTYPE_ARP);
  uint16_t hardware_type = arp_hdr->hardware_type;
  uint16_t protocol_type = arp_hdr->protocol_type;
  uint8_t hardware_size = arp_hdr->hardware_size;
  uint8_t protocol_size = arp_hdr->protocol_size;
  uint16_t opcode = htons(OP_REPLY);
  inet_aton(ip, &src_addr); /* convert string to in_addr_t */
  dest_addr = arp_hdr->sender_ip_addr;

  memcpy(new_packet, ethernet_hdr->src, MAC_ADDR_LEN); /* Ethernet fields */
  memcpy(new_packet + MAC_ADDR_LEN, mac, MAC_ADDR_LEN);
  memcpy(new_packet + (2 * MAC_ADDR_LEN), &type, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE, &hardware_type, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 2, &protocol_type, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 4, &hardware_size, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 5, &protocol_size, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 6, &opcode, 2);

  /*sender mac - Spoofed*/
  memcpy(new_packet + ETHERNET_HDR_SIZE + 8, mac, MAC_ADDR_LEN);
  /* Sender IP - Spoofed*/
  memcpy(new_packet + ETHERNET_HDR_SIZE + 14, &src_addr, 4);
  /* Target mac*/
  memcpy(new_packet + ETHERNET_HDR_SIZE + 18, ethernet_hdr->src, MAC_ADDR_LEN);
  /* target ip */
  memcpy(new_packet + ETHERNET_HDR_SIZE + 24, &dest_addr, 4);

  if ((sendPacket(new_packet, (size_t)(ETHERNET_HDR_SIZE + 28))) != 0)
    fprintf(stderr, "Error in sendPacket()\n");

}

/******************************************************************************
 * This method determines if received packet is our packet of interest. We are
 * interested in ARP Requests and ICMP Echo (ping) requests.
 * 
 * @param u_char *args
 * @param const struct pcap_pkthdr *header
 * @param const u_char *packet - received packet
 *****************************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  struct ethernet_header *ethernet_hdr;
  ethernet_hdr = (struct ethernet_header *)packet;

  if (ntohs(ethernet_hdr->type) == ETHERTYPE_IP) {

    if (validPacket(TYPE_IP, packet) == 1) 
      constructSendICMP(packet);
    else
      return;

  } else if (ntohs(ethernet_hdr->type) == ETHERTYPE_ARP) {

    if (validPacket(TYPE_ARP, packet) == 1)
      constructSendARP(packet);       
    else 
      return;

  } else {

     return;

  }

  return;

}

/******************************************************************************
 * This method checks for valid arguments in the CLI.
 *****************************************************************************/
void checkArgs(int argc, char **argv) {

  memset(ip, 0, 16);
  memset(mac ,0, MAC_ADDR_LEN);

  if (argc != 3) {
    fprintf(stderr, "*** error: usage: ./ping_spoof <spoofed ip> <spoofed-mac>\n");
    exit(EXIT_FAILURE);
  }

  if (strlen(argv[1]) > 17) {
    fprintf(stderr, "*** error: please enter valid MAC Address\n");
    exit(EXIT_FAILURE);
  }

  if (strlen(argv[2]) > 15) {
    fprintf(stderr, "*** error: please enter valid IP address\n");
    exit(EXIT_FAILURE);
  }


  memcpy(ip, argv[2], 15);

  sscanf(argv[1], "%x:%x:%x:%x:%x:%x", (unsigned int *) &mac[0],
                                       (unsigned int *) &mac[1],
                                       (unsigned int *) &mac[2],
                                       (unsigned int *) &mac[3],
                                       (unsigned int *) &mac[4],
                                       (unsigned int *) &mac[5]);

  return;

}

/******************************************************************************
 * A method to catch SIGINT ctr-c and frees memory on exit.
 *****************************************************************************/
void terminate() {

  pcap_close(handle);
  exit(EXIT_SUCCESS);

}

/******************************************************************************
 * MAIN
 *****************************************************************************/
int main(int argc, char **argv)
{

  char errbuf[PCAP_ERRBUF_SIZE];     /* Error string */
  bpf_u_int32 mask;		     /* The netmask of our sniffing device */
  bpf_u_int32 net;		     /* The IP of our sniffing device */

  checkArgs(argc, argv);

  /* Find and define the capture device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  /* Define device properties */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  signal(SIGINT, terminate);
  memcpy(ip, argv[2], 15);

  /* Open session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }

  /* Set callback function */
  pcap_loop(handle, LOOP, got_packet, NULL);

  return 0;

}
