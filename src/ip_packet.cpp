#include "ip_packet.hpp"
#include <iomanip>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "utils.hpp"

IPHelper::~IPHelper() {
    
}

std::string getIP(int family, const void *address)
{
    char buffer[256] = {0};
    const char *ip = inet_ntop(family, address, buffer, 256);
    if (ip == NULL)
    {
        throw std::runtime_error(std::strerror(errno));
    }

    return std::string(ip);
}

void IPHelper::init(const uint8_t *packet)
{
    if (ntohs(frame->ether_type) == ETHERTYPE_IP)
    {
        auto ip = (struct ip *)(packet + sizeof(*frame));
        sourceAddress = getIP(AF_INET, &(ip->ip_src));
        destinationAddress = getIP(AF_INET, &(ip->ip_dst));
        tcpOffset = ip->ip_hl * 4;
        fragmentOffset = ip->ip_off;
        version = 4;
        length = ntohs(ip->ip_len);
        identification = std::to_string(ntohs(ip->ip_id));
    }
    else if (ntohs(frame->ether_type) == ETHERTYPE_IPV6)
    {
        auto ip = (struct ip6_hdr *)(packet + sizeof(*frame));
        sourceAddress = getIP(AF_INET6, &(ip->ip6_src));
        destinationAddress = getIP(AF_INET6, &(ip->ip6_dst));
        version = 6;
        length = ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(*ip);
        handleIp6Extensions(ip, packet);
    }
    else
    {
        throw std::runtime_error("Unsupported ethernet type - " + std::to_string(ntohs(frame->ether_type)));
    }
}

std::string IPHelper::getSourceAddress()
{
    return sourceAddress;
}

std::string IPHelper::getDestinationAddress()
{
    return destinationAddress;
}

int IPHelper::getOffsetToTransportLayer()
{
    return tcpOffset;
}

std::string IPHelper::getIdentification()
{
    return identification;
}

uint16_t IPHelper::getLength() const {
    return length;
}

uint16_t IPHelper::getFragmentOffset()
{
    if (version == 4)
    {
        auto removeFlags = fragmentOffset & 0x1000;
        auto newOffset = ntohs(removeFlags);
        return (((newOffset & 0xFF00) >> 3) | (newOffset & 0x00FF)) * 8;
    }
    else if (version == 6)
    {
        return ntohs((fragmentOffset & 0xFF00) | ((fragmentOffset & 0x00FF) >> 3)) * 8; // remove RES + M
    }
    else {
        throw std::runtime_error("Unsupported version: " + version);
    }
}

bool IPHelper::hasMoreFragments()
{
    if (version == 4)
    {
        return (fragmentOffset & 0x2000) == 1; 
    }
    else if (version == 6)
    {
        return (fragmentOffset & 0x0001) == 1;
    }
    else {
        throw std::runtime_error("Unsupported version: " + version);
    }
}

void IPHelper::handleIp6Extensions(struct ip6_hdr *ip, const uint8_t *packet)
{
    const u_char *start = packet + sizeof(*frame);
    int offset = sizeof(*ip);
    auto nextHeader = ip->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    while (nextHeader != IPPROTO_TCP)
    {
        if (start + offset >= start + packetLength)
        {
            throw std::runtime_error("End of packet");
        }

        switch (nextHeader)
        {
        case IPPROTO_HOPOPTS:
        {
            auto header = (struct ip6_hbh *)(start + offset);
            nextHeader = ntohs(header->ip6h_nxt);
            offset += sizeof(*header);
            break;
        }
        case IPPROTO_ROUTING:
        {
            auto header = (struct ip6_rthdr *)(start + offset);
            nextHeader = ntohs(header->ip6r_nxt);
            offset += sizeof(*header);
            break;
        }
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_MH:
        case IPPROTO_HIPV2:
        case IPPROTO_SHIM6:
        case IPPROTO_RESERVED1:
        case IPPROTO_RESERVED2:
            throw std::runtime_error("Not implemented. " + nextHeader);
            break;
        case IPPROTO_DSTOPTS:
        {
            auto header = (struct ip6_ext *)(start + offset);
            nextHeader = ntohs(header->ip6e_nxt);
            offset += sizeof(*header);
            break;
        }
        case IPPROTO_FRAGMENT:
        {
            auto header = (struct ip6_frag *)(start + offset);
            nextHeader = ntohs(header->ip6f_nxt);
            offset += sizeof(*header);
            identification = ntohl(header->ip6f_ident);
            fragmentOffset = header->ip6f_offlg;
            break;
        }
        default:
            throw std::runtime_error("Not implemented. " + nextHeader);
            break;
        }
    }
    tcpOffset = offset;
}