#pragma once
#include <string>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pcap.h>

#define IPPROTO_HIPV2 (139)
#define IPPROTO_SHIM6 (140)
#define IPPROTO_RESERVED1 (253)
#define IPPROTO_RESERVED2 (254)

class IPHelper {
    private:
        const int packetLength;
        const struct ether_header *frame;
        std::string sourceAddress;
        std::string destinationAddress;
        std::string identification;
        /**
         * Payload length
         */
        uint16_t length;
        uint16_t fragmentOffset;
        /**
         * IP version
         */ 
        uint8_t version;
        /**
         * offset from ip header to tcp header
         */ 
        int tcpOffset;
        void init(const uint8_t *packet);
        void handleIp6Extensions(struct ip6_hdr *ip, const uint8_t *packet);

    public:
        IPHelper(const u_char *packet, const int packetLength, const struct ether_header *frame) : packetLength(packetLength), frame(frame) {
            init(packet);
        }
        ~IPHelper();
        std::string getSourceAddress();
        std::string getDestinationAddress();
        std::string getIdentification();
        uint16_t getLength() const;
        uint16_t getFragmentOffset();
        bool hasMoreFragments();
        /**
         * get offset from ip header to tcp header
         */ 
        int getOffsetToTransportLayer();
};