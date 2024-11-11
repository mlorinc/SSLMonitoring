#pragma once
#include <cstdint>

namespace tls::handshake
{

    enum ExtensionType : uint16_t
    {
        SNI = 0,
        SIGNATURE_ALGORITHMS = 13
    };

    enum NameType : uint8_t
    {
        HOST_NAME = 0
    };

    #define EXTENSION_SIZE (4)

    struct Extension
    {
        ExtensionType type;
        uint16_t length;
        // opaque extension_data<0..2 ^ 16 - 1>;
    };

    #define SERVER_NAME_SIZE (5)

    struct ServerName
    {
        uint16_t listLength; // not used practically
        enum NameType nameType;
        uint16_t hostNameLength;
    };
} // namespace tls::handshake