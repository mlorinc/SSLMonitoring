#include "session.hpp"
#include <ctime>
#include <iostream>

namespace tcp
{
    Session::Session(std::shared_ptr<Packet> first)
    {
        firstPacket = first;
        lastSourcePacket = firstPacket;
        packetCount = 1;
    }

    Session::~Session()
    {
    }

    tls::parser::TlsParser::PayloadLengthType Session::getTlsPayloadLength() const
    {
        return clientParser.getTlsPayloadLength() + serverParser.getTlsPayloadLength();
    }

    std::string Session::getSourceAddress() const
    {
        return firstPacket->getSourceAddress();
    }

    std::string Session::getDestinationAddress() const
    {
        return firstPacket->getDestinationAddress();
    }

    std::string Session::getSNI() const
    {
        return clientParser.getSNI();
    }

    uint16_t Session::getSourcePort() const
    {
        return firstPacket->getSourcePort();
    }

    uint16_t Session::getDestinationPort() const
    {
        return firstPacket->getDestinationPort();
    }

    size_t Session::getPacketsCount() const
    {
        return packetCount;
    }

    std::string Session::getTimestamp() const
    {
        char buffer[64] = {0};
        auto header = firstPacket->getPcapHeader();
        auto time = std::localtime(&(header.ts.tv_sec));
        std::strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", time);
        return std::string(buffer) + "." + std::to_string(header.ts.tv_usec);
    }

    SessionId Session::getSessionId() const
    {
        return firstPacket->getSessionId();
    }

    std::string Session::getDuration() const
    {
        if (!lastPacket)
        {
            return "-";
        }
        
        auto start = firstPacket->getPcapHeader();
        auto end = lastPacket->getPcapHeader();

        decltype(end.ts.tv_usec) micro = 0;

        if (end.ts.tv_usec > start.ts.tv_usec)
        {
            micro = end.ts.tv_usec - start.ts.tv_usec;
        }
        else {
            micro = start.ts.tv_usec - end.ts.tv_usec;
        }
        
        return std::to_string(end.ts.tv_sec - start.ts.tv_sec) + "." + std::to_string(micro);
    }

    bool Session::isClosed() const {
        return sourceClosed && destinationClosed;
    }

    bool Session::add(std::shared_ptr<Packet> packet)
    {
        if (isClosed())
        {
            return false;
        }
        
        if (packet->getTcpPacket()->rst)
        {
            packetCount++;
            this->lastPacket = packet;
            sourceClosed = true;
            destinationClosed = true;
            return true;
        }

        auto &parser = isFromSource(*packet) ? clientParser : serverParser;
        auto &lastPacket = isFromSource(*packet) ? lastSourcePacket : lastDestinationPacket;
        auto &finPacket = isFromSource(*packet) ? sourceFin : destinationFin;
        auto &oppositeFinPacket = isFromSource(*packet) ? destinationFin : sourceFin;
        auto &closeFlag = isFromSource(*packet) ? destinationClosed : sourceClosed;

        if (!lastPacket && packet->getTcpPacket()->syn)
        {
            lastPacket = packet;
            return true;
        }

        auto nextSequence = lastPacket->getSequence() + lastPacket->getPayloadLength();

        if (lastPacket->getTcpPacket()->syn || lastPacket->getTcpPacket()->fin)
        {
            nextSequence = lastPacket->getSequence() + 1;
        }

        if (nextSequence == packet->getSequence())
        {
            if (packet->getPayloadLength() > 0)
            {
                try
                {
                    // std::cerr << "Handling: " << packet->getInternetPacket().getIdentification() << std::endl;
                    parser.feed(packet->getPayload().get(), packet->getPayloadLength());
                }
                catch (std::exception &e)
                {
                    // std::cerr << e.what() << std::endl;
                }
            }
            else
            {
                if (!finPacket && packet->getTcpPacket()->fin)
                {
                    finPacket = packet;
                    this->lastPacket = packet;
                }
                if (oppositeFinPacket && packet->getSequence() == oppositeFinPacket->getAcknowledgment()) {
                    closeFlag = true;
                }
            }
            lastPacket = packet;
        }
        else if (nextSequence > packet->getSequence())
        {
            throw OutOfOrderPacket("Out of order packet with ip id: " + packet->getInternetPacket().getIdentification());
        }
        else
        {
            return false;
        }
        packetCount++;
        return true;
    }

    bool Session::isFromSource(const Packet &packet)
    {
        if(getSourcePort() == packet.getSourcePort() && getSourceAddress() == packet.getSourceAddress()) {
            return true;
        }
        else if (getDestinationPort() == packet.getSourcePort() && getDestinationAddress() == packet.getSourceAddress()) {
            return false;
        }
        else {
            throw std::runtime_error("Logic error");
        }
    }
} // namespace tcp