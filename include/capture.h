#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_MAX_LEN 30 // This wasn't here

// Full definition so C++ knows the struct
struct MonitorData {
    char ip[IP_MAX_LEN]; // was const char *ip
    int port;
};

struct tcpHandshake {
    uint32_t synSeq;
    uint32_t synAckSeq;
    //int auto_ack_enabled;
};

typedef struct {
    char time[32];
    char srcIP[64];
    char dstIP[64];
    char protocol[16];
    int srcPort;
    int dstPort;
    int length;
    unsigned char flags; // For TCP flags if applicable
} PacketInfo;

//typedef std::function<void(const char*)> PacketDisplayCallback;
typedef std::function<void(const char*)> PacketDisplayCallback;
//typedef std::function<void(const PacketInfo*)> PacketDisplayCallback;
void registerPacketDisplayCallback(PacketDisplayCallback cb);

typedef void (*SendAckCallback)();
void handleSynAckPacket();
//void registerSendAckCallback(SendAckCallback cb);
void onSynAckReceived();
uint32_t get_syn_seq(void);
uint32_t get_synack_seq(void);
void set_auto_ack_enabled(int enabled);
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int start_capture(const char *adapterName, struct MonitorData *md);


#ifdef __cplusplus
}
#endif

#endif // CAPTURE_H
