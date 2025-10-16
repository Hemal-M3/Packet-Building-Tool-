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

// UDP Header
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;    // header + data
    uint16_t checksum;  // optional for IPv4, mandatory for IPv6
};

// Pseudo Header for UDP checksum
struct pseudo_udp_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_len;
};

//Checksum calculation
uint16_t udpChecksum(uint16_t* ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
        sum += *(uint8_t*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Convert string IP to uint32_t
uint32_t udpStringToIp(const char ipAddress[50]) {
    return inet_addr(ipAddress);
}

// Send custom UDP packet
int send_UDP_packet(const char adapterName[512],
                    uint16_t src_port, uint16_t dst_port,
                    uint16_t udp_length, uint16_t udp_checksum,
                    uint8_t ip_ver_ihl, uint8_t ip_tos, uint16_t ip_tot_len,
                    uint16_t ip_id, uint16_t ip_frag_off, uint8_t ip_ttl,
                    uint8_t ip_protocol, const char src_ip_addr[50], const char dst_ip_addr[50],
                    uint8_t src_mac[6], uint8_t dst_mac[6], uint16_t ethType)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    pcap_t* handle = pcap_open_live(adapterName, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("Unable to open adapter: %s\n", errbuf);
        return 1;
    }

    uint8_t packet[1500];
    memset(packet, 0, sizeof(packet));

    struct eth_header* eth = (struct eth_header*)packet;
    struct ip_header* ip = (struct ip_header*)(packet + 14);
    struct udp_header* udp = (struct udp_header*)(packet + 14 + ((ip_ver_ihl & 0x0F) * 4));

    // --- Ethernet Header ---
    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->eth_type = htons(ethType);

    // --- IP Header ---
    ip->ver_ihl = ip_ver_ihl;
    ip->tos = ip_tos;
    ip->tot_len = htons(ip_tot_len);
    ip->id = htons(ip_id);
    ip->frag_off = htons(ip_frag_off);
    ip->ttl = ip_ttl;
    ip->protocol = ip_protocol;
    ip->src_ip = inet_addr(src_ip_addr);
    ip->dst_ip = inet_addr(dst_ip_addr);

    if (ip->checksum == 0)
        ip->checksum = udpChecksum((uint16_t*)ip, (ip->ver_ihl & 0x0F) * 4);

    // --- UDP Header ---
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    //uint16_t udp_len = 8;
    udp->length = htons(udp_length);
    udp->checksum = udp_checksum;

    // --- UDP checksum calculation if 0 ---
    if (udp_checksum == 0) {
        struct pseudo_udp_header psh;
        psh.src_ip = ip->src_ip;
        psh.dst_ip = ip->dst_ip;
        psh.zero = 0;
        psh.protocol = ip_protocol;
        psh.udp_len = htons(udp_length);

        uint8_t pseudo_packet[sizeof(struct pseudo_udp_header) + udp_length];
        memcpy(pseudo_packet, &psh, sizeof(psh));
        memcpy(pseudo_packet + sizeof(psh), udp, 8); // header only, no payload yet
        udp->checksum = udpChecksum((uint16_t*)pseudo_packet, sizeof(pseudo_packet));
    }

    // Send packet
    if (pcap_sendpacket(handle, packet, 14 + ntohs(ip->tot_len)) != 0) {
        printf("Send failed: %s\n", pcap_geterr(handle));
    } else {
        printf("UDP packet sent.\n");
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
