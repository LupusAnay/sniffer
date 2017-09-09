//
// Created by LupusAnay on 16.08.17.
//

#ifndef SNIFFER_PACKET_H
#define SNIFFER_PACKET_H

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <iostream>

using namespace std;

class Packet {
public:
    Packet(const unsigned char *pack, const struct pcap_pkthdr *hdr);
    static const int SIZE_ETH;
    const char *getPayload();
private:
    const unsigned char *packet;

    struct PacketOptions {
        ether_header *ethData{};
        ip *ipData{};
        tcphdr *tcpData{};
        udphdr *udpData{};
    } packetOptions; // Contain all parts of tcp/udp packet
    const struct pcap_pkthdr *header; // Packet header, contain header len, packet len etc.
    const char *payload;

    void readEthHdr();
    void readIpHdr();
    void readProto();
};

#endif //SNIFFER_PACKET_H
