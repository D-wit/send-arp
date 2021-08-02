#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


EthArpPacket arpRequest(EthArpPacket s_packet, char* sip, char* dip, char* smac);

EthArpPacket arpReply(EthArpPacket s_packet, char* vict_ip, char* dip, char* smac, uint8_t* dmac);
