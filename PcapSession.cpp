//
// Created by LupusAnay on 16.08.17.
//

#include "PcapSession.h"
#include "Packet.h"

// public:

void PcapSession::startSession(const char *filter, char *device_name, unsigned int packet_count){
    descriptor = initPcapSession(filter, device_name);
    startSniffing(packet_count);
}

void PcapSession::closeSession(){
    pcap_close(descriptor);
}

// private:
pcap_t *PcapSession::initPcapSession(const char *filter, char *device_name)
{
    bpf_u_int32 mask, net; // mask and address for our device
    char errorBuf[PCAP_ERRBUF_SIZE]; // string for contain error codes
    struct bpf_program fp{}; // compiled pcap filter
    pcap_t* handle; // session descriptor

    char* dev = device_name;

    if(dev == nullptr)
    { perror("Couldn't find this device"); }

    if (pcap_lookupnet(dev, &net, &mask, errorBuf) == -1)
    { perror("Looking netmask for device"); }

    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 100, errorBuf)) == nullptr)
    { perror("Opening device"); }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    { perror("Couldn't compile filter"); }

    if (pcap_setfilter(handle, &fp) == -1)
    { perror("Couldn't set filter"); }

    return handle;
}

void PcapSession::startSniffing(unsigned int packet_count)
{
    pcap_loop(descriptor, packet_count, &loopCallback, nullptr);
}

void PcapSession::loopCallback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *pack)
{
    cout << "\nWe got a packet! The data: " << endl;
    Packet packet = Packet(pack, header);
    cout << packet.getPayload() << endl;
}
