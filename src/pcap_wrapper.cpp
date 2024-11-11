#include "pcap_wrapper.hpp"
#include "pcap_error.hpp"

PcapWrapper::PcapWrapper(std::string interface,
                         PcapMode mode,
                         const int BUFFER_SIZE,
                         bool promiscuous,
                         const int timeout)
{

    if (mode == PcapMode::LIVE)
    {
        handler = pcap_open_live(interface.c_str(), BUFFER_SIZE, promiscuous, timeout, errbuf);
    }
    else {
        handler = pcap_open_offline(interface.c_str(), errbuf);
    }

    if (handler == NULL)
    {
        throw PcapError("Could not open interface " + interface + ". Reason: " + std::string(errbuf), 2);
    }

    if (pcap_datalink(handler) != DLT_EN10MB)
    {
        throw PcapError("Interface " + interface + " does not support L2 headers.", 2);
    }

    if (mode == PcapMode::OFFLINE)
    {
        return;
    }
    
    if (pcap_lookupnet(interface.c_str(), &network, &mask, errbuf) == -1)
    {
        throw PcapError("Could not get network information on interface: " + interface + ". Reason: " + std::string(errbuf), 2);
    }
}

PcapWrapper::~PcapWrapper()
{
    if (handler)
    {
        pcap_close(handler);
        handler = nullptr;
    }
}

void PcapWrapper::setFilter(std::string filter, bool optimize)
{
    struct bpf_program bpf;
    if (pcap_compile(handler, &bpf, filter.c_str(), optimize, network) == -1)
    {
        throw PcapError("Invalid filter: " + filter + ". Reason: " + pcap_geterr(handler), 2);
    }

    if (pcap_setfilter(handler, &bpf) == -1)
    {
        throw PcapError("Could not set filter: " + filter + ". Reason: " + pcap_geterr(handler), 2);
    }
}

int PcapWrapper::startLoop(PcapWrapper::LoopCallback callback, int packetCount, u_char *args)
{
    int result = pcap_loop(handler, packetCount, callback, args);

    if (result == PCAP_ERROR)
    {
        throw PcapError(pcap_geterr(handler), 2);
    }

    return result;
}