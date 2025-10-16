#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include "windivert.h"


#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// Ethernet Header
struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

// IP Header
struct ip_header {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// TCP Header.111
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

// Pseudo Header for TCP checksum
/* When calculating the TCP checksum, the checksum itself is replaced by zeros, why are other checksums
 uint16_t while this one is uint8_t? https://www.ietf.org/rfc/rfc793.txt*/
struct pseudo_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};

uint16_t checksum(uint16_t* ptr, int nbytes) {
    long sum = 0;
    // Continue untill all data is split and added up
    // Remove 2 bytes every iteration
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) // Last byte added
        sum += *(uint8_t*)ptr;
    // Ones complement addition (overflow added back)
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    // Return Checksum
    return (uint16_t)(~sum);
}

uint32_t stringToIp(const char ipAddress[50]) {
  return inet_addr(ipAddress);
}

int send_syn_packet(const char adapterName[512], uint16_t src_port_front, uint16_t dst_port_front,
                    uint32_t seq_num_front, uint32_t ack_seq_front, uint8_t data_offset_front, uint8_t data_shift_front,
                    uint8_t flags_front, uint16_t window_front, uint16_t urgent_ptr_front, uint8_t ver_ihl_front,
                    uint8_t tos_front, uint16_t tot_len_front, uint16_t id_front, uint16_t frag_off_front, uint8_t ttl_front,
                    uint8_t protocol_front, const char src_ip_addr_front[50], const char dst_ip_addr_front[50],
                    uint8_t src_mac_front[6], uint8_t dst_mac_front[6], uint16_t ethType_front) {
    //const char* networkDevice =  "\\Device\\NPF_{37B1DE87-7E49-4499-B221-4D0E5C5D85CC}";
    //printf("Original network device: %s", networkDevice);
    //printf("Network device from front end: %s", adapterName);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * device;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }
    //printf("This is a test!");
    HANDLE handlee = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handlee == INVALID_HANDLE_VALUE) {
            printf("Failed to open WinDivert. Error code: %lu\n", GetLastError());
            return 1;
        }
        printf("\nWinDivert opened successfully!\n");
        WinDivertClose(handlee);


    // Pick the first interface
    device = alldevs;
    pcap_t* handle = pcap_open_live(adapterName, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("Unable to open adapter: %s\n", errbuf);
        return 1;
    }

    uint8_t packet[60];
    memset(packet, 0, sizeof(packet));

    struct eth_header* eth = (struct eth_header*)packet;
    struct ip_header* ip = (struct ip_header*)(packet + 14);
    struct tcp_header* tcp = (struct tcp_header*)(packet + 34);

    // Ethernet
    //uint8_t dst_mac[6] = {0xB2, 0xD7, 0x92, 0x05, 0x16, 0xBE}; // Router MAC // was {0xB2, 0xD7, 0x92, 0x05, 0x16, 0xBE}
    //uint8_t src_mac[6] = src_mac_front;                        // Your MAC  // was {0x80, 0x30, 0x49, 0x4C, 0x13, 0xD3}
    memcpy(eth->dst_mac, dst_mac_front, 6);
    memcpy(eth->src_mac, src_mac_front, 6);
    eth->eth_type = htons(ethType_front); // IPv4 // was 0x0800
    printf("\nInside C EthType: %04x", htons(ethType_front));
    printf("\nINSIDE CCCCCCCCCCC\n");

    // IP
    // TOS https://linuxreviews.org/Type_of_Service_(ToS)_and_DSCP_Values
    ip->ver_ihl = ver_ihl_front; // was 0x45
    ip->tos = tos_front; // was 0x00
    ip->tot_len = htons(tot_len_front); // 20 IP + 20 TCP  was 40
    ip->id = htons(id_front); // was 54321
    ip->frag_off = htons(frag_off_front); // was 0x4000 // 0x4000, 0x8000 and 0 work, rest  don't work
    ip->ttl = ttl_front; // was 64
    ip->protocol = protocol_front; // TCP was 6
    ip->checksum = 0;
    ip->src_ip = inet_addr(src_ip_addr_front); // Your IP was "192.168.0.29"
    ip->dst_ip = inet_addr(dst_ip_addr_front); // Google IP (example) was "192.168.0.72"
    ip->checksum = checksum((uint16_t*)ip, 20);
    // Need to add options

    // TCP
    //flags_front = 0x01;
    tcp->src_port = htons(src_port_front);
    tcp->dst_port = htons(dst_port_front);
    tcp->seq = htonl(seq_num_front); // was 0
    tcp->ack_seq = htonl(ack_seq_front); // was 0
    tcp->data_offset = (data_offset_front << data_shift_front); // 5 * 4 = 20 bytes (was 5 << 4)
    tcp->flags = flags_front;                           /* FIN: 0x01 | SYN: 0x02 | RST: 0x04 | PSH: 0x08
                                                           ACK: 0x10 | URG: 0x20 | SYN + ACK: 0x12
                                                           FIN + ACK  0x11 | FIN + PSH + ACK: 0x19 */
    tcp->window = htons(window_front); // was 65535
    tcp->checksum = 0;
    tcp->urg_ptr = urgent_ptr_front; // was 0

    // Pseudo Header + TCP for checksum
    struct pseudo_header psh;
    psh.src_ip = ip->src_ip;
    psh.dst_ip = ip->dst_ip;
    psh.zero = 0;
    psh.protocol = 6;
    psh.tcp_len = htons(20); // 20 is fixed for SYN only

    uint8_t pseudo_packet[sizeof(struct pseudo_header) + 20];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, 20);
    tcp->checksum = checksum((uint16_t*)pseudo_packet, sizeof(pseudo_packet));
    // if (autoChecsum_front) {
    //     tcp->checksum = checksum((uint16_t*)pseudo_packet, sizeof(pseudo_packet));
    // }
    //   else {
    //     Do manual checksum with values provided;
    // }

    // Send it
    if (pcap_sendpacket(handle, packet, 54) != 0) { // 54
        printf("Send failed: %s\n", pcap_geterr(handle));
    } else {
        printf("SYN packet sent.\n");
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
