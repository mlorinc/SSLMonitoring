#pragma once
#include <string>
#include <list>
#include <map>
#include <memory>
#include "session_id.hpp"
#include "packet.hpp"
#include "tls_parser.hpp"

namespace tcp
{
    class OutOfOrderPacket : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    class Session
    {
    public:
        /**
         * Create new session. First argument must be SYN packet.
         */ 
        Session(std::shared_ptr<Packet> first);
        ~Session();
        std::string getSourceAddress() const;
        std::string getDestinationAddress() const;
        std::string getSNI() const;
        /**
         * Get client port
         */ 
        uint16_t getSourcePort() const;
        /**
         * Get server port
         */ 
        uint16_t getDestinationPort() const;
        /**
         * Return packet count in this sessions
         */ 
        std::list<Packet>::size_type getPacketsCount() const;
        /**
         * Get total length of TLS packets
         */ 
        tls::parser::TlsParser::PayloadLengthType getTlsPayloadLength() const;
        /**
         * Attempt to add packet to session. Returns false when packet does not match seq number or true when packet was accepted.
         * If packet SEQ number is less than latest accepted packet, OutOfOrderPacket exception is thrown.
         */
        bool add(std::shared_ptr<Packet> packet);
        /**
         * Get timestamp of SYN packet
         */ 
        std::string getTimestamp() const;
        /**
         * Get duration of sessions. Returns "-" if session was not finished properly.
         */ 
        std::string getDuration() const;
        /**
         * Return sessionID. Not related to SSL sessionID.
         */ 
        SessionId getSessionId() const;
        /**
         * Test if connection is closed
         */ 
        bool isClosed() const;
    private:
        std::shared_ptr<Packet> firstPacket, lastPacket;
        std::shared_ptr<Packet> lastSourcePacket, lastDestinationPacket;
        std::shared_ptr<Packet> sourceFin, destinationFin;
        size_t packetCount = 0;
        tls::parser::TlsParser clientParser;
        tls::parser::TlsParser serverParser;
        bool sourceClosed = false;
        bool destinationClosed = false;
        bool isFromSource(const Packet &packet);
    };
} // namespace tcp
