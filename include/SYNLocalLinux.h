#ifndef SYNLOCALLINUX_H
#define SYNLOCALLINUX_H

#ifdef __cplusplus
extern "C" {
#endif

int send_syn_packet(const char adapterName[512], uint16_t port, uint16_t dst_port,
                    uint32_t seq_num, uint32_t ack_seq, uint8_t data_offset, uint8_t data_shift,
                    uint8_t flags, uint16_t window, uint16_t urg_ptr, uint8_t ver_ihl, uint8_t tos,
                    uint16_t tot_len, uint16_t id_front, uint16_t frag_off_front, uint8_t ttl_front,
                    uint8_t protocol_front, const char src_ip_addr_front[50], const char dst_ip_addr_front[50],
                    uint8_t srcMac[6], uint8_t dstMac[6], uint16_t ethType);

uint16_t checksum(uint16_t* ptr, int nbytes);

uint32_t stringToIp(const char ipAddress[50]);

#ifdef __cplusplus
}
#endif

#endif // SYNLOCALLINUX_H
