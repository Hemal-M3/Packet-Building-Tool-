#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>  // For strcmp, strcpy
#include <cstdio>
#include <cstring>
#include <ctime>
#include "capture.h"

static SendAckCallback sendAckCallback = 0;

void registerSendAckCallback(SendAckCallback cb) {
    sendAckCallback = cb;
}

void onSynAckReceived() {
    if (sendAckCallback) {
        sendAckCallback();
    }
}

// Ethernet header
struct eth_header {
    u_char dst[6];
    u_char src[6];
    u_short type;
};

// IPv4 header (simplified)
struct ip_header {
    u_char ihl_ver;       // Version + IHL
    u_char tos;           // Type of service
    u_short tlen;         // Total length
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    u_short crc;
    struct in_addr src_ip;
    struct in_addr dst_ip;
};

// TCP header (simplified)
struct tcp_header {
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack_seq;
    u_char data_offset;
    u_char flags;
    u_short win;
    u_short checksum;
    u_short urg_ptr;
};

struct udp_header {
    u_short src_port;
    u_short dst_port;
    u_short len;
    u_short checksum;
};

char buf[1024];

static PacketDisplayCallback packetDisplayCallback = nullptr;

void registerPacketDisplayCallback(PacketDisplayCallback cb) {
    packetDisplayCallback = cb;
}

//helper function to call frontend safely
void displayPacket(const char *text) {
    if (packetDisplayCallback) {
        packetDisplayCallback(text);  // calls the frontend
    }
}

// void displayPacket(const PacketInfo *info) {
//     if (packetDisplayCallback) {
//         packetDisplayCallback(info);  // pass struct
//     }
// }


// Struct to hold monitored IP and port
// struct MonitorData {
//     char ip[32]; // was const char *ip
//     int port;
// };

// struct tcpHandshake {
//     uint32_t synSeq;
//     uint32_t synAckSeq;
//     int auto_ack_enabled;
// };

static struct tcpHandshake handshake = {0, 0};

uint32_t get_syn_seq(void) {
    return handshake.synSeq;
}

uint32_t get_synack_seq(void) {
    return handshake.synAckSeq;
}
// Callback function called by pcap_loop for each packet
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    printf("Inside packet_handler\n"); fflush(stdout);
    struct MonitorData *md = (struct MonitorData*)user;
    const char *monitored_ip = md->ip;
    int monitored_port = md->port;

    // Parse Ethernet
    struct eth_header *eth = (struct eth_header*)bytes;

    // Check if the packet is IPv4
    if (ntohs(eth->type) == 0x0800) {
        struct ip_header *ip = (struct ip_header*)(bytes + 14);

        char src_ip[16], dst_ip[16];
        strcpy(src_ip, inet_ntoa(ip->src_ip));
        strcpy(dst_ip, inet_ntoa(ip->dst_ip));

        if (strcmp(src_ip, monitored_ip) == 0 || strcmp(dst_ip, monitored_ip) == 0) { // was src_ip, monitored_ip and dst_ip, monitored_ip
            printf("\nThis is the Original Test1\n--- Captured packet, length=%d bytes ---\n", h->len);
            printf("IP src=%s -> dst=%s proto=%d\n", src_ip, dst_ip, ip->proto);

            // TCP example
            if (ip->proto == 6) {
                struct tcp_header *tcp = (struct tcp_header*)(bytes + 14 + ((ip->ihl_ver & 0x0F) * 4));

                if (ntohs(tcp->src_port) == monitored_port || ntohs(tcp->dst_port) == monitored_port) {

                    sprintf(buf,
                            "TCP:%s:%d:%s:%d:%u:%u:0x%02X"
                            "|ETH:dst=%02x:%02x:%02x:%02x:%02x:%02x,src=%02x:%02x:%02x:%02x:%02x:%02x,type=0x%04x"
                            "|IP:ver=%d,ihl=%d,tos=%d,len=%d,id=%d,flags=0x%04x,ttl=%d,proto=%d,checksum=0x%04x,src=%s,dst=%s"
                            "|TCP:srcport=%d,dstport=%d,seq=%u,ack=%u,offset=%d,flags=0x%02x,win=%d,checksum=0x%04x,urgptr=%d",
                            // Table part
                            src_ip, ntohs(tcp->src_port),
                            dst_ip, ntohs(tcp->dst_port),
                            ntohl(tcp->seq), ntohl(tcp->ack_seq),
                            tcp->flags,

                            // Ethernet
                            eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5],
                            eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5],
                            ntohs(eth->type),

                            // IP
                            (ip->ihl_ver >> 4), (ip->ihl_ver & 0x0F), ip->tos, ntohs(ip->tlen), ntohs(ip->identification),
                            ntohs(ip->flags_fo), ip->ttl, ip->proto, ntohs(ip->crc),
                            src_ip, dst_ip,

                            // TCP
                            ntohs(tcp->src_port), ntohs(tcp->dst_port),
                            ntohl(tcp->seq), ntohl(tcp->ack_seq),
                            (tcp->data_offset >> 4), tcp->flags, ntohs(tcp->win), ntohs(tcp->checksum), ntohs(tcp->urg_ptr)
                            );
                    displayPacket(buf);


                    if (tcp->flags == 0x02) {
                        handshake.synSeq = ntohl(tcp->seq);
                        printf("\n\n[SYN captured] SEQ = %u\n\n", handshake.synSeq);
                    }
                    else if (tcp->flags == 0x12) {
                        handshake.synAckSeq = ntohl(tcp->seq);
                       printf("\n\n[SYN-ACK captured] SEQ = %u, ACK = %u\n\n", handshake.synAckSeq, ntohl(tcp->ack_seq));
                    }

                    printf("TCP src port=%d dst port=%d flags=0x%02x\n",
                           ntohs(tcp->src_port), ntohs(tcp->dst_port), tcp->flags);
                    printf("TCP: %d -> %d\n", ntohs(tcp->src_port), ntohs(tcp->dst_port));
                    printf("Seq: %u, Ack: %u, DataOffset: %d, Flags: 0x%02x, Window: %d\n",
                           ntohl(tcp->seq), ntohl(tcp->ack_seq),
                           (tcp->data_offset >> 4) * 4,
                           tcp->flags, ntohs(tcp->win));
                    if (tcp->flags == 0x02) {
                        printf("Matched SYN packet!\n");
                    }

                }
            }
            // Check if the protocol is udp
            else if (ip->proto == 17) {
                struct udp_header *udp = (struct udp_header*)(bytes + 14 + ((ip->ihl_ver & 0x0F) * 4));

                if (ntohs(udp->src_port) == monitored_port || ntohs(udp->dst_port) == monitored_port) {
                    sprintf(buf,
                            "UDP:%s:%d:%s:%d:-:-:-"
                            "|ETH:dst=%02x:%02x:%02x:%02x:%02x:%02x,src=%02x:%02x:%02x:%02x:%02x:%02x,type=0x%04x"
                            "|IP:ver=%d,ihl=%d,tos=%d,len=%d,id=%d,flags=0x%04x,ttl=%d,proto=%d,checksum=0x%04x,src=%s,dst=%s"
                            "|UDP:srcport=%d,dstport=%d,len=%d,checksum=0x%04x",
                            // Table part
                            src_ip, ntohs(udp->src_port),
                            dst_ip, ntohs(udp->dst_port),

                            // Ethernet
                            eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5],
                            eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5],
                            ntohs(eth->type),

                            // IP
                            (ip->ihl_ver >> 4), (ip->ihl_ver & 0x0F), ip->tos, ntohs(ip->tlen), ntohs(ip->identification),
                            ntohs(ip->flags_fo), ip->ttl, ip->proto, ntohs(ip->crc),
                            src_ip, dst_ip,

                            // UDP
                            ntohs(udp->src_port), ntohs(udp->dst_port),
                            ntohs(udp->len), ntohs(udp->checksum)
                            );
                    displayPacket(buf);
                    printf("%s\n", buf);
                }
            }
        }
    }
}

// Start capture on an adapter with frontend IP and port
int start_capture(const char *adapterName, struct MonitorData *md) {
    printf("NOW WE ARE IN STAR_CAPTURE\n");
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(adapterName, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("Unable to open adapter: %s\n", errbuf);
        return 1;
    }

    // Build BPF filter using frontend values
    struct bpf_program fcode;
    char filter_exp[128];
    printf("-----Filter IP: %s, Port: %d\n", md->ip, md->port);
    //sprintf(filter_exp, "tcp and host %s and port %d", md->ip, md->port);

    sprintf(filter_exp, "(tcp or udp) and host %s and port %d", md->ip, md->port);

    //sprintf(filter_exp, "tcp");
    //sprintf(filter_exp, "tcp and host 192.168.0.29 and port 3333");
    if (pcap_compile(handle, &fcode, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        printf("pcap_compile error\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fcode) < 0) {
        printf("pcap_setfilter error\n");
        return 1;
    }

    printf("Starting capture on %s with filter=%s...\n", adapterName, filter_exp);

    // Pass struct pointer as 'user' to packet_handler
    pcap_loop(handle, 0, packet_handler, (u_char*)md);

    pcap_close(handle);
    return 0;
}

