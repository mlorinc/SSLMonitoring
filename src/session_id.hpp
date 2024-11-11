#pragma once
#include <string>
#include <cstdint>

namespace tcp
{
    /**
     * TCP session helper struct
     */ 
    struct SessionId
    {
        std::string sourceAddress;
        std::string destinationAddress;
        uint16_t sourcePort;
        uint16_t destinationPort;

        /**
         * swap addresses and ports
         */ 
        void flip();
        std::string toString() const;
    };

    extern bool operator<(const tcp::SessionId &lhs, const tcp::SessionId &rhs);
    extern bool operator==(const tcp::SessionId &lhs, const tcp::SessionId &rhs);
} // namespace tcp