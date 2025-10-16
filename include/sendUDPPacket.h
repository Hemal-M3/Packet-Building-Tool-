#ifndef SENDUDPPACKET_H
#define SENDUDPPACKET_H
#include <stdint.h>

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
    uint16_t length;    // header + payload
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

// Function declarations
#ifdef __cplusplus
extern "C" {
#endif

uint16_t udpChecksum(uint16_t* ptr, int nbytes);
uint32_t stringToIp(const char ipAddress[50]);

// Updated send_UDP_packet: matches frontend fields (Ethernet + IP + UDP)
int send_UDP_packet(const char adapterName[512],
                    uint16_t src_port, uint16_t dst_port,
                    uint16_t udp_length, uint16_t udp_checksum,
                    uint8_t ip_ver_ihl, uint8_t ip_tos, uint16_t ip_tot_len,
                    uint16_t ip_id, uint16_t ip_frag_off, uint8_t ip_ttl,
                    uint8_t ip_protocol, const char src_ip_addr[50], const char dst_ip_addr[50],
                    uint8_t src_mac[6], uint8_t dst_mac[6], uint16_t ethType);

#ifdef __cplusplus
}
#endif

#endif // SENDUDPPACKET_H

