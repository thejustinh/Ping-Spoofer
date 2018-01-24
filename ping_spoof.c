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
  * @return 0 on success, -1 otherwise
  ****************************************************************************/
int sendPacket(uint8_t * packet, size_t packet_length) {

      struct ifreq ifidx;                   // interface index
      struct sockaddr_ll dest_addr;                        // target address
      int sd, i;                                       // raw socket descriptor


      /* make a raw socket */
      if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
          perror("[-] Error! Cannot create raw socket");
          return -1;
      }

      /* Get the index of the interface to send on */
      strncpy(ifidx.ifr_name, dev, strlen(dev));      // set interface name
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
      else
          printf( "[+] Spoofed Ethernet frame sent successfully!\n");

      return 0;                                           // success!

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
  printf("\n\t\tNew Packet Size: %d\n", packet_size);

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

  /* Testing Variables */
  uint16_t testType; memset(&testType, 0, 2);
  struct ip_header *ip_test;
  struct icmp_header *icmp_test;
  int saved_checksum;
  int icmp_saved_checksum;

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
  memcpy(new_packet + ETHERNET_HDR_SIZE + 28, packet + ETHERNET_HDR_SIZE + 28, packet_size - (ETHERNET_HDR_SIZE + 28));


  /* Save IP Checksum */
  checksum = in_cksum((unsigned short *)(new_packet + ETHERNET_HDR_SIZE), 20);
  memcpy(new_packet + ETHERNET_HDR_SIZE + 10, &checksum, 2);

  /* Save ICMP Checksum */
  icmp_checksum = in_cksum((unsigned short *)(new_packet + ETHERNET_HDR_SIZE + 20),
                    packet_size - ETHERNET_HDR_SIZE - IP_MIN_HDR_SIZE);

  memcpy(new_packet + ETHERNET_HDR_SIZE + 22, &icmp_checksum, 2);

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
  printf("\t\tTotal Length (IP): %d\n", ntohs(ip_test->tot_len));
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

  printf("\t\tSource IP: %s\n", inet_ntoa(ip_test->source_addr));
  printf("\t\tDest IP: %s\n", inet_ntoa(ip_test->dest_addr));


  icmp_test = (struct icmp_header *) (new_packet + ETHERNET_HDR_SIZE + IP_MIN_HDR_SIZE);

  if (icmp_test->type == 0x0)
     printf("\t\tICMP Type: Reply (Correct)\n");
  else if (icmp_test->type == 0x08)
     printf("\t\tICMP Type: Request\n");
  else
     printf("\t\tICMP Type: %d\n", icmp_test->type);

  icmp_saved_checksum = icmp_test->checksum;
  icmp_test->checksum = 0;
  icmp_test->checksum = in_cksum((unsigned short *)icmp_test,
        packet_size - ETHERNET_HDR_SIZE - IP_MIN_HDR_SIZE);

  printf("\t\tICMP Code (0): %d\n", icmp_test->code);
  if (icmp_saved_checksum == (int)icmp_test->checksum)
    printf("\t\tICMP Checksum: Correct (0x%04x)\n", ntohs(icmp_saved_checksum));
  else
    printf("\t\tICMP Checksum: Incorrect (0x%04x)\n", ntohs(icmp_saved_checksum));

  printf("\t\tICMP ID: %d\n", ntohs(icmp_test->identifier));
  printf("\t\tICMP Sequence #: %d\n", ntohs(icmp_test->seq_num));

  if ((sendPacket(new_packet, (size_t)packet_size)) == 0)
    printf("Successful packet sent!\n");
}

void constructSendARP(const u_char *packet) {
  /*Var tests */
  const struct arp_header *arp_test;
  uint16_t testType;
  /* End var tests */

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

  printf("\t\tConstructing ARP Packet...");
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
  if (ntohs(testType) == ETHERTYPE_ARP) {
    printf("\n\t\tType: ARP (correct)\n");
  } else {
    printf("\n\t\tTYPE: UNKNOWN *****************");
  }

  arp_test = (struct arp_header *)(new_packet + ETHERNET_HDR_SIZE);

  printf("\t\tHardware Type (1): %d\n", ntohs(arp_test->hardware_type));
  printf("\t\tProtocol Type (2048): %d\n", ntohs(arp_test->protocol_type));
  printf("\t\tHardware Size (6): %d\n", arp_test->hardware_size);
  printf("\t\tProtocol Size (4): %d\n", arp_test->protocol_size);

  if (ntohs(arp_test->opcode) == REQUEST)
     printf("\t\tOpcode: Request\n");
  else
     printf("\t\tOpcode: Reply (correct)\n");
/*
  printf("\t\tSender MAC: %s\n",
     ether_ntoa((struct ether_addr *)&arp_test->sender_mac_addr));
  printf("\t\tSender IP: %s\n", inet_ntoa(arp_test->sender_ip_addr));
  printf("\t\tTarget MAC: %s\n",
     ether_ntoa((struct ether_addr *)&arp_test->target_mac_addr));
  printf("\t\tTarget IP: %s\n\n", inet_ntoa(arp_test->target_ip_addr));
*/

  if ((sendPacket(new_packet, (size_t)(ETHERNET_HDR_SIZE + 28))) == 0)
    printf("Successful ARP sent!\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  static int count = 1;
  struct ethernet_header *ethernet_hdr;

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

    constructSendICMP(packet);

  } else if (ntohs(ethernet_hdr->type) == ETHERTYPE_ARP) {

     printf("Type: ARP\n");
     if (validPacket(TYPE_ARP, packet) == 1) {
       // Consruct ARP reply
       printf("\n\t\tPacket is for my spoofed IP!\n");
     } else {
       printf("\t\tPacket Dropped\n");
       return;
     }

     constructSendARP(packet);

  } else {

     printf("Type: unknown\n");
     return;

  }

  return;
}

void checkArgs(int argc, char **argv) {

  memset(ip, 0, 16);
  memset(mac ,0, MAC_ADDR_LEN);

  if (argc != 3) {
    printf("*** error: usage: ./ping_spoof <spoofed ip> <spoofed-mac>\n");
    exit(EXIT_FAILURE);
  }

  memcpy(ip, argv[2], 15);

  sscanf(argv[1], "%x:%x:%x:%x:%x:%x", (unsigned int *) &mac[0],
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
  //char *dev = NULL;		                 /* Device to sniff on */
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
