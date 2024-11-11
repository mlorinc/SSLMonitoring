#include "tls.hpp"
#include <stdexcept>

namespace tls
{
    RecordProtocol::RecordProtocol() {}

    std::string RecordProtocol::getVersion()
    {
        return version;
    }

    enum ContentType RecordProtocol::getContentType()
    {
        return type;
    }

    decltype(TLSPlaintext::length) RecordProtocol::getRecordProtocolLength()
    {
        return length;
    }

    void RecordProtocol::setVersion(ProtocolVersion version)
    {
        this->version = parseVersion(version);
    }

    void RecordProtocol::setContentType(enum ContentType type)
    {
        this->type = type;
    }

    void RecordProtocol::setRecordProtocolLength(decltype(TLSPlaintext::length) length)
    {
        this->length = ntohs(length);
    }

} // namespace tls
