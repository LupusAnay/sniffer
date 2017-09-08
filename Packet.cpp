//
// Created by LupusAnay on 16.08.17.
//

#include "Packet.h"


Packet::Packet(const unsigned char *pack, const struct pcap_pkthdr *hdr){
    packet = pack;
    header = hdr;
    readEthHdr();
    readIpHdr();
    readProto();
};

const char *Packet::getPayload(){
    return payload;
}

// Take data from packet address and put it into ether_header struct
void Packet::readEthHdr() {
    packetOptions.ethData = (struct ether_header *) packet;
}

// Same principe with ether_header, but address of IP header is behind the address of Eth header,
// so add size of Eth header to the packet address for get IP data
void Packet::readIpHdr(){
    packetOptions.ipData = (struct ip *)(packet + SIZE_ETH);
}

// Same principe, but
// length of ip, tcp, or udp header is a count of 4-byte words in the special field,
// like ip_hl, or th_off. Need to multiply this count on 4 to get size in bytes
void Packet::readProto(){
    if(packetOptions.ipData->ip_p == IPPROTO_TCP)
    {
        packetOptions.tcpData = (struct tcphdr *)(packet + SIZE_ETH + packetOptions.ipData->ip_hl*4);
        payload = (char *)(packet + SIZE_ETH + packetOptions.ipData->ip_hl*4 + packetOptions.tcpData->th_off*4);
    }
    else if (packetOptions.ipData->ip_p == IPPROTO_UDP)
    {
        packetOptions.udpData = (struct udphdr *)(packet + SIZE_ETH + packetOptions.ipData->ip_hl*4);
        payload = (char *)(packet + SIZE_ETH + packetOptions.ipData->ip_hl*4 + packetOptions.udpData->uh_ulen);
    }
    else {
        cout << "It's no tcp or udp packet." << endl;
        return;
    }
}
