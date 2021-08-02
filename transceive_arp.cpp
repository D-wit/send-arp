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




EthArpPacket arpRequest(EthArpPacket s_packet, char* sip, char* dip, char* smac)
{

    EthArpPacket packet = s_packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = Mac(smac); //Source_MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac);  //Source_MAC
    packet.arp_.sip_ = htonl(Ip(sip));  //Source_IP
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(Ip(dip)); //Target_IP

    return packet;
}

EthArpPacket arpReply(EthArpPacket s_packet, char* vict_ip, char* dip, char* smac, uint8_t* dmac)
{

    EthArpPacket packet = s_packet;

    packet.eth_.dmac_ = Mac(dmac); //Target_MAC
    packet.eth_.smac_ = Mac(smac); //Source_MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(smac);  //Source_MAC
    packet.arp_.sip_ = htonl(Ip(dip));  //Source_IP
    packet.arp_.tmac_ = Mac(dmac); //Target_MAC
    packet.arp_.tip_ = htonl(Ip(vict_ip)); //Target_IP

    return packet;
}
