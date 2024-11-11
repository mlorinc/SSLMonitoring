#pragma once
#include <string>
#include <cstdio>
#include <pcap.h>
#include "pcap_mode.hpp"

class PcapWrapper
{
private:
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    bpf_u_int32 network, mask;

public:
    using LoopCallback = void(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    /**
     * Create wrapper around pcap library
     * interface - network interface or file path to pcapng
     * BUFFER_SIZE - pcap buffer size
     * promiscuous - promiscuous mode flag
     */ 
    PcapWrapper(std::string interface,
                PcapMode mode = PcapMode::LIVE,
                const int BUFFER_SIZE = BUFSIZ,
                bool promiscuous = true,
                const int timeout = 3000);
    /**
     * Set pcap filter
     */ 
    void setFilter(std::string filter, bool optimize = true);

    /**
     * Start capturing packets
     */ 
    int startLoop(PcapWrapper::LoopCallback callback, int packetCount = -1, u_char *args = NULL);
    ~PcapWrapper();
};
