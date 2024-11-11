#include "session_id.hpp"

namespace tcp
{
    void SessionId::flip()
    {
        std::swap(sourceAddress, destinationAddress);
        std::swap(sourcePort, destinationPort);
    }

    std::string SessionId::toString() const {
        return sourceAddress + ":" + std::to_string(sourcePort) + ":" + destinationAddress + ":" + std::to_string(destinationPort);
    }

    extern bool operator<(const tcp::SessionId &lhs, const tcp::SessionId &rhs)
    {
        return (&lhs == &rhs) ||
               (lhs.sourceAddress == rhs.sourceAddress &&
                lhs.destinationAddress == rhs.destinationAddress &&
                lhs.sourcePort == rhs.sourcePort &&
                lhs.destinationPort == rhs.destinationPort);
    }
    extern bool operator==(const tcp::SessionId &lhs, const tcp::SessionId &rhs)
    {
        return (&lhs == &rhs) ||
               (lhs.sourceAddress == rhs.sourceAddress &&
                lhs.destinationAddress == rhs.destinationAddress &&
                lhs.sourcePort == rhs.sourcePort &&
                lhs.destinationPort == rhs.destinationPort);
    }
} // namespace tcp
