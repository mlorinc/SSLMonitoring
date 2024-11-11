#include "packet.hpp"
#include <stdexcept>

Packet::Packet(const u_char *packet, const struct pcap_pkthdr pcapHeader) : pcapHeader(pcapHeader)
{
    // ignore const
    memcpy(&ethernet, packet, sizeof(ethernet));
    ipHelper = std::unique_ptr<IPHelper>(new IPHelper(packet, pcapHeader.len, getEthernetHeader()));
    memcpy(&tcp, packet + sizeof(struct ether_header) + ipHelper->getOffsetToTransportLayer(), sizeof(tcp));

    auto applicationDataOffset = sizeof(struct ether_header) + ipHelper->getOffsetToTransportLayer() + tcp.doff * 4;
    
    if (ipHelper->getLength() != 0)
    {
        payloadLength = ipHelper->getLength() - ipHelper->getOffsetToTransportLayer() - tcp.doff * 4;
    }
    else {
        payloadLength = pcapHeader.len - applicationDataOffset; 
    }

    if (payloadLength > 0)
    {
        this->applicationLayerPayload = std::shared_ptr<const u_char>(new u_char[payloadLength]);
        std::memcpy((void *)this->applicationLayerPayload.get(), packet + applicationDataOffset, payloadLength);
    }
};

const struct ether_header *Packet::getEthernetHeader() const
{
    return &ethernet;
}

IPHelper Packet::getInternetPacket() const
{
    return *ipHelper;
}

const struct tcphdr *Packet::getTcpPacket() const
{
    return &tcp;
}

std::string Packet::getSourceAddress() const
{
    return ipHelper->getSourceAddress();
}

std::string Packet::getDestinationAddress() const
{
    return ipHelper->getDestinationAddress();
}

decltype(tcphdr::source) Packet::getSourcePort() const
{
    return ntohs(tcp.source);
}

decltype(tcphdr::dest) Packet::getDestinationPort() const
{
    return ntohs(tcp.dest);
}

decltype(tcphdr::seq) Packet::getSequence() const
{
    return ntohl(tcp.seq);
}

decltype(tcphdr::ack_seq) Packet::getAcknowledgment() const
{
    return ntohl(tcp.ack_seq);
}

std::shared_ptr<const u_char> Packet::getPayload() const
{
    return applicationLayerPayload;
}

size_t Packet::getPayloadLength() const
{
    return payloadLength;
}

struct pcap_pkthdr Packet::getPcapHeader() const
{
    return pcapHeader;
}

tcp::SessionId Packet::getSessionId() const
{
    // sourceIP:destIP:sourcePort:destPort => Session
    return (tcp::SessionId){
        .sourceAddress = this->getSourceAddress(),
        .destinationAddress = this->getDestinationAddress(),
        .sourcePort = this->getSourcePort(),
        .destinationPort = this->getDestinationPort()};
}