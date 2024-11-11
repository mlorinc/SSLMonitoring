#pragma once
#include <cstdint>
#include <memory>
#include "tls.hpp"
#include "handshake_extension.hpp"

namespace tls::parser
{
    // Finite automat states
    enum ParserState
    {
        RECORD_LAYER_TYPE,
        RECORD_LAYER_VERSION,
        RECORD_LAYER_LENGTH,
        HANDSHAKE_TYPE,
        HANDSHAKE_VERSION,
        HANDSHAKE_LENGTH,
        SKIP_TO_SESSION_ID,
        SKIP_TO_CIPHER_SUITED,
        SKIP_TO_COMPRESSION_METHODS,
        SKIP_TO_EXTENSIONS_LENGTH,
        SESSION_ID,
        CIPHER_SUITED,
        COMPRESSION_METHODS,
        EXTENSIONS_LENGTH,
        SKIP_HANDSHAKE,
        EXTENSION_TYPE,
        EXTENSION_LENGTH,
        SNI_EXTENSION_LIST_LENGTH,
        SNI_EXTENSION_NAME_TYPE,
        SNI_EXTENSION_NAME_LENGTH,
        SNI_EXTENSION_NAME,
        SKIP_RECORD_LAYER
    };

    // Handshake helper struct
    struct HandshakeData
    {
        uint32_t length;
        struct ProtocolVersion version;
        uint16_t extensionLength;
        uint16_t cipherLength;
        uint8_t sessionIdLength;
        uint8_t compressionMethodLength;
        enum HandshakeType type;
    };

    class TlsParserError : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    class TlsParser
    {
    public:
        using PayloadLengthType = unsigned long long;
    private:
        /** Helper variables **/
        ParserState state = ParserState::RECORD_LAYER_TYPE;
        size_t feedOffset = 0;
        size_t feedSize = 0;
        size_t skipFeed = 0;

        const uint8_t *feedData;
        size_t acceptOffset = 0;
        RecordProtocol recordProtocol;

        struct TLSPlaintext recordProtocolHelper;
        struct HandshakeData handshakeData;
        struct tls::handshake::Extension extension;
        struct tls::handshake::ServerName sniData;
        size_t extensionsLengthRead = 0;
        std::unique_ptr<uint8_t> sni;
        /** end of Helper variables **/

        bool sniCaptured = false;
        bool serverHello = false;
        PayloadLengthType tlsPayloadLength = 0;

        bool accept(uint8_t &variable);
        bool accept(uint16_t &variable);
        bool accept(uint32_t &variable);
        bool accept(enum ContentType &variable);
        bool accept(struct ProtocolVersion &variable);
        bool accept(enum HandshakeType &variable);
        bool accept(enum tls::handshake::ExtensionType &variable);
        bool accept(enum tls::handshake::NameType &variable);
        bool accept(uint8_t *data, size_t size);
        void skip(size_t count);
        void back(size_t count);

    public:
        TlsParser();
        ~TlsParser();
        /**
         * Add data to stream. Must be in correct order.
         */ 
        void feed(const u_char *data, size_t size);
        /**
         * Close stream. Unused at this moment.
         */ 
        void close();
        /**
         * Get sni. If not present, TlsParserError.
         */ 
        std::string getSNI() const;
        /**
         * Test if sni is present
         */ 
        bool hasSNI() const;
        /**
         * Test if parser server hello in past
         */ 
        bool hadServerHello() const;
        /**
         * Get cumulative payload length
         */ 
        PayloadLengthType getTlsPayloadLength() const;
    };
} // namespace tls::parser
