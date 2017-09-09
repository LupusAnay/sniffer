//
// Created by LupusAnay on 16.08.17.
//

#ifndef SNIFFER_PCAPSESSION_H
#define SNIFFER_PCAPSESSION_H

#include <pcap.h>

class PcapSession{

public:
    void startSession(const char *filter, char *device_name, unsigned int packet_count);
    void closeSession();

private:
    pcap_t *descriptor {};

    pcap_t *initPcapSession(const char *filter, char *device_name);
    void startSniffing(unsigned int packet_count);
    static void loopCallback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *pack);
};

#endif //SNIFFER_PCAPSESSION_H
