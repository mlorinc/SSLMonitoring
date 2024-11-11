#pragma once
#include <pcap.h>
#include <memory>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <cstring>
#include "ip_packet.hpp"
#include "tls.hpp"
#include "session_id.hpp"

class Packet
{
private:
    std::shared_ptr<const u_char> applicationLayerPayload;
    const struct pcap_pkthdr pcapHeader;
    struct ether_header ethernet;
    struct tcphdr tcp;
    size_t payloadLength;
    std::unique_ptr<IPHelper> ipHelper{nullptr};

public:
    Packet(const u_char *packet, const struct pcap_pkthdr pcapHeader);
    const struct ether_header *getEthernetHeader() const;
    IPHelper getInternetPacket() const;
    const struct tcphdr *getTcpPacket() const;
    /**
     * Get application layer payload
     */ 
    std::shared_ptr<const u_char> getPayload() const;
    /**
     * Get application layer payload size
     */ 
    size_t getPayloadLength() const;
    std::string getSourceAddress() const;
    std::string getDestinationAddress() const;
    decltype(tcphdr::source) getSourcePort() const;
    decltype(tcphdr::dest) getDestinationPort() const;
    decltype(tcphdr::seq) getSequence() const;
    decltype(tcphdr::ack_seq) getAcknowledgment() const;
    struct pcap_pkthdr getPcapHeader() const;
    /**
     * Get tcp identification used for session packet lookup
     */ 
    tcp::SessionId getSessionId() const;
};
