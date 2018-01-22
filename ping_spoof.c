/*******************************
 * CPE 465 - Program 1 - ping_spoof.c
 * Winter 2018
 *
 * @author Justin Herrera
 ******************************/

#include "ping_spoof.h"

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
      printf("\n\t\tARP Reply packet...\n");
      return 0;
    }

  } else if (type == TYPE_IP) {

    // Define IP and ICMP header
    ip_hdr = (struct ip_header *)(packet + ETHERNET_HDR_SIZE);
    icmp_hdr = (struct icmp_header *)(packet + ETHERNET_HDR_SIZE + ((ip_hdr->ver_hdr_len & 0x0f) *4));

    // Drop packet if we received ICMP reply (only respond to echo requests)
    if (icmp_hdr->type != 0x08) {
      printf("\n\t\tICMP Response packet...\n");
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
  if (strncmp((const char *)ip, (const char *)ip_buf, 15) != 0) {
    printf("\n\t\tPacket not for me..\n");
    return 0;
  }

  return 1;

}

void constructICMP(const u_char *packet, uint8_t * new_packet) {

  const struct ethernet_header *ethernet_hdr;
  const struct ip_header *ip_hdr;
  ethernet_hdr = (struct ethernet_header *) packet;
  ip_hdr = (struct ip_header *) (packet + ETHERNET_HDR_SIZE);

  uint16_t type = htons(ETHERTYPE_IP);
  uint8_t version_header = 0x45;
  uint8_t diffserv = 0x00;
  uint16_t total_length = htons(0x0054); /* 84 in decimal */
  uint16_t id = htons(9999); /* random ID */
  uint16_t frag = 0x0000;
  uint8_t ttl = 0x40;
  uint8_t protocol = 0x01;
  uint16_t checksum = 0x0000;
  uint32_t src_addr = inet_addr(ip);
  uint32_t dest_addr = inet_addr(inet_ntoa(ip_hdr->source_addr));

  /* Testing Variables */
  uint16_t testType; memset(&testType, 0, 2);
  struct ip_header *ip_test;
  int saved_checksum;

  /* copy source mac address of sender into new packet's destination field */
  memcpy(new_packet, ethernet_hdr->src, MAC_ADDR_LEN);

  /* copy spoofed mac address into new packet's source field */
  memcpy(new_packet + MAC_ADDR_LEN, mac, MAC_ADDR_LEN);

  /* copy Ethernet ARP type into packet in network order */
  memcpy(new_packet + (2 * MAC_ADDR_LEN), &type, 2);

  memcpy(new_packet + ETHERNET_HDR_SIZE, &version_header, 1); /* Copy Version / Header */
  memcpy(new_packet + ETHERNET_HDR_SIZE + 1, &diffserv, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 2, &total_length, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 4, &id, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 6, &frag, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 8, &ttl, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 9, &protocol, 1);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 10, &checksum, 2);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 12, &src_addr, 4);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 12, &dest_addr, 4);

  checksum = htons(in_cksum((unsigned short *)(new_packet + ETHERNET_HDR_SIZE), 20));
  memcpy(new_packet + ETHERNET_HDR_SIZE + 10, &checksum, 2);

  printf("\t\tConstructing ICMP Packet...");
  printf("\n\t\tDestination MAC: %x:%x:%x:%x:%x:%x", new_packet[0],
                                                     new_packet[1],
                                                     new_packet[2],
                                                     new_packet[3],
                                                     new_packet[4],
                                                     new_packet[5]);

  printf("\n\t\tSource MAC: %x:%x:%x:%x:%x:%x", new_packet[6],
                                                new_packet[7],
                                                new_packet[8],
                                                new_packet[9],
                                                new_packet[10],
                                                new_packet[11]);

  memcpy(&testType, new_packet + (2 * MAC_ADDR_LEN), 2);
  if (ntohs(testType) == ETHERTYPE_IP) {
    printf("\n\t\tType: IP\n");
  } else {
    printf("\n\t\tTYPE: UNKNOWN *****************");
  }

  ip_test = (struct ip_header *)(new_packet + ETHERNET_HDR_SIZE);

  printf("\t\tIP Version (4): %d\n", (ip_test->ver_hdr_len & 0xf0) >> 4);
  printf("\t\tHeader Len (20): %d\n", (ip_test->ver_hdr_len&0x0f) * 4);
  printf("\t\tTOS subfields:\n");
  printf("\t\t   Diffserv bits (0): %d\n", (ip_test->diffserv_ecn) >> 2);
  printf("\t\t   ECN bits (0): %d\n", (ip_test->diffserv_ecn & 0x03));
  printf("\t\tTTL (64): %d\n", ip_test->ttl);
  if ((ip_test->protocol) == 0x06)
     printf("\t\tProtocol: TCP\n");
  else if (ip_test->protocol == 0x01)
     printf("\t\tProtocol: ICMP\n");
  else if (ip_test->protocol == 0x11)
     printf("\t\tProtocol: UDP\n");
  else
     printf("\t\tProtocol: Unknown\n");

  saved_checksum = ip_test->checksum;
  ip_test->checksum = 0;
  ip_test->checksum = in_cksum((unsigned short *)ip_test,
     (ip_test->ver_hdr_len & 0x0f) * 4);

  if (saved_checksum == (int)ip_test->checksum)
     printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(saved_checksum));
  else
     printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(saved_checksum));

  printf("\t\tSource IP: %s\n", inet_ntoa(ip));
  printf("\t\tDest (from) IP: %s\n", inet_ntoa(ip_test->dest_addr));

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  static int count = 1;
  struct ethernet_header *ethernet_hdr;
  uint8_t new_packet[ICMP_PACKETSIZE];

  printf("\nPacket number %d: ", count);
  count++;

  ethernet_hdr = (struct ethernet_header *)packet;

  if (ntohs(ethernet_hdr->type) == ETHERTYPE_IP) {

    printf("Type: IP -> ICMP\n");
    if (validPacket(TYPE_IP, packet) == 1) {
      // Consruct ICMP reply
      printf("\n\t\tPacket is for my spoofed IP!\n");
    } else {
      printf("\t\tPacket Dropped\n");
      return;
    }

    /* construct ICMP reply */
    constructICMP(packet, new_packet);


  } else if (ntohs(ethernet_hdr->type) == ETHERTYPE_ARP) {

     printf("Type: ARP\n");
     if (validPacket(TYPE_ARP, packet) == 1) {
       // Consruct ARP reply
       printf("\n\t\tPacket is for my spoofed IP!\n");
     } else {
       printf("\t\tPacket Dropped\n");
       return;
     }

     /* Send ARP Response */

  } else {

     printf("Type: unknown\n");
     return;

  }

  /* Send Packet */

  return;
}

void checkArgs(int argc, char **argv) {

  memset(ip, 0, 16);
  memset(mac ,0, MAC_ADDR_LEN);

  if (argc != 3) {
    printf("*** error: usage: ./ping_spoof <spoofed ip> <spoofed-mac>\n");
    exit(EXIT_FAILURE);
  }

  memcpy(ip, argv[1], 15);

  sscanf(argv[2], "%x:%x:%x:%x:%x:%x", (unsigned int *) &mac[0],
                                       (unsigned int *) &mac[1],
                                       (unsigned int *) &mac[2],
                                       (unsigned int *) &mac[3],
                                       (unsigned int *) &mac[4],
                                       (unsigned int *) &mac[5]);

  printf("IP: %s", ip);
  printf("\nMAC: %x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return;
}

int main(int argc, char **argv)
{
  pcap_t *handle;		                   /* Session handle */
  char *dev = NULL;		                 /* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	     /* Error string */
  struct bpf_program fp;		           /* The compiled filter expression */
  char filter_exp[] = "icmp or arp";	 /* The filter expression */
  bpf_u_int32 mask;		                 /* The netmask of our sniffing device */
  bpf_u_int32 net;		                 /* The IP of our sniffing device */

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

  /* Open session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }

  /* Compile and apply filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  /* Grab a packet */
  /* packet = pcap_next(handle, &header); */
  /* Print its length */
  /*printf("Jacked a packet with length of [%d]\n", header.len);
  */

  /* now we can set our callback function */
  pcap_loop(handle, LOOP, got_packet, NULL);

  /* cleanup */
  pcap_freecode(&fp);

  /* And close the session */
  pcap_close(handle);

  return 0;
}
