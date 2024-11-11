#include "tls_parser.hpp"
#include <cstring>
#include <iostream>
#include "utils.hpp"

namespace tls::parser
{
    TlsParser::TlsParser()
    {
    }

    TlsParser::~TlsParser()
    {
    }

    void TlsParser::skip(size_t count)
    {
        if (acceptOffset != 0)
        {
            throw std::runtime_error("Cannot skip when accept offset is set.");
        }

        skipFeed += count;
    }

    void TlsParser::back(size_t count) {
        if (acceptOffset != 0)
        {
            throw std::runtime_error("Cannot back when accept offset is set.");
        }

        // there is more data to skip than go back
        if (skipFeed >= count)
        {
            skipFeed -= count;
        }
        // there is some data to skip but it is less than back
        else {
            if (skipFeed != 0)
            {
                count -= skipFeed;
            }

            if (feedOffset < count)
            {
                throw TlsParserError("Cannot go back. Data are unavailable.");
            }
            
            // no data to skip (we moved back)
            skipFeed = 0;
            feedOffset -= count;
        }
    }

    void TlsParser::feed(const u_char *data, size_t size)
    {
        feedData = data;
        feedSize = size;
        feedOffset = 0;

        while (feedOffset < size)
        {
            if (feedOffset + skipFeed >= size)
            {
                skipFeed -= size - feedOffset;
                break;
            }
            else {
                feedOffset += skipFeed;
                skipFeed = 0;
            }

            switch (state)
            {
            case ParserState::RECORD_LAYER_TYPE:
                if (accept(recordProtocolHelper.type))
                {
                    recordProtocol.setContentType(recordProtocolHelper.type);
                    state = ParserState::RECORD_LAYER_VERSION;
                }
                break;
            case ParserState::RECORD_LAYER_VERSION:
                if (accept(recordProtocolHelper.version))
                {
                    state = ParserState::RECORD_LAYER_LENGTH;
                    recordProtocol.setVersion(recordProtocolHelper.version);
                }
                break;
            case ParserState::RECORD_LAYER_LENGTH:
                if (accept(recordProtocolHelper.length))
                {
                    recordProtocol.setRecordProtocolLength(recordProtocolHelper.length);
                    tlsPayloadLength += recordProtocol.getRecordProtocolLength();
                    // std::cerr << "Length: " << recordProtocol.getRecordProtocolLength() << std::endl;
                    if (recordProtocolHelper.type == ContentType::HANDSHAKE)
                    {
                        state = ParserState::HANDSHAKE_TYPE;
                    }
                    else
                    {
                        skip(recordProtocol.getRecordProtocolLength());
                        state = ParserState::RECORD_LAYER_TYPE;
                    }
                }
                break;
            case ParserState::HANDSHAKE_TYPE:
                if (accept(handshakeData.type))
                {
                    state = ParserState::HANDSHAKE_LENGTH;
                }
                break;
            case ParserState::HANDSHAKE_VERSION:
                if (accept(handshakeData.version))
                {
                    skip(RANDOM_SIZE);
                    state = ParserState::SESSION_ID;
                    RecordProtocol::parseVersion(handshakeData.version);
                }
                break;
            case ParserState::HANDSHAKE_LENGTH:
                if (accept(handshakeData.length))
                {
                    // move one byte back because handshake length has 3 bytes
                    back(1);

                    uint32_t result = 0;
                    result |= (handshakeData.length & 0x00FF0000) >> 16;
                    result |= (handshakeData.length & 0x000000FF) << 16;
                    result |= (handshakeData.length & 0x0000FF00);

                    handshakeData.length = result;

                    if (handshakeData.type != HandshakeType::CLIENT_HELLO)
                    {
                        skip(handshakeData.length);
                        state = ParserState::RECORD_LAYER_TYPE;
                    }
                    else
                    {
                        if (handshakeData.type == HandshakeType::SERVER_HELLO)
                        {
                            serverHello = true;
                        }

                        state = ParserState::HANDSHAKE_VERSION;
                    }
                }
                break;
            case ParserState::SESSION_ID:
                if (accept(handshakeData.sessionIdLength))
                {
                    skip(handshakeData.sessionIdLength);
                    state = ParserState::CIPHER_SUITED;
                }
                break;
            case ParserState::CIPHER_SUITED:
                if (accept(handshakeData.cipherLength))
                {
                    handshakeData.cipherLength = ntohs(handshakeData.cipherLength);
                    skip(handshakeData.cipherLength);
                    state = ParserState::COMPRESSION_METHODS;
                }
                break;
            case ParserState::COMPRESSION_METHODS:
                if (accept(handshakeData.compressionMethodLength))
                {
                    skip(handshakeData.compressionMethodLength);
                    state = ParserState::EXTENSIONS_LENGTH;
                }
                break;
            case ParserState::EXTENSIONS_LENGTH:
                if (accept(handshakeData.extensionLength))
                {
                    handshakeData.extensionLength = ntohs(handshakeData.extensionLength);
                    state = ParserState::EXTENSION_TYPE;
                }
                break;
            case ParserState::EXTENSION_TYPE:
                if (extensionsLengthRead >= handshakeData.extensionLength)
                {
                    state = ParserState::RECORD_LAYER_TYPE;
                }
                else if (accept(extension.type))
                {
                    extension.type = static_cast<tls::handshake::ExtensionType>(ntohs(extension.type));
                    state = ParserState::EXTENSION_LENGTH;
                }
                break;
            case ParserState::EXTENSION_LENGTH:
                if (accept(extension.length))
                {
                    extension.length = ntohs(extension.length);
                    extensionsLengthRead += extension.length + 4;

                    if (extension.type == tls::handshake::ExtensionType::SNI)
                    {
                        if (sniCaptured)
                        {
                            throw TlsParserError("SNI is already captured.");
                        }

                        state = ParserState::SNI_EXTENSION_LIST_LENGTH;
                    }
                    else
                    {
                        skip(extension.length);
                        state = ParserState::EXTENSION_TYPE;
                    }
                }
                break;
            case ParserState::SNI_EXTENSION_LIST_LENGTH:
                if (accept(sniData.listLength))
                {
                    sniData.listLength = ntohs(sniData.listLength);
                    state = ParserState::SNI_EXTENSION_NAME_TYPE;
                }
                break;
            case ParserState::SNI_EXTENSION_NAME_TYPE:
                if (accept(sniData.nameType))
                {
                    state = ParserState::SNI_EXTENSION_NAME_LENGTH;
                }
                break;
            case ParserState::SNI_EXTENSION_NAME_LENGTH:
                if (accept(sniData.hostNameLength))
                {
                    sniData.hostNameLength = ntohs(sniData.hostNameLength);
                    state = ParserState::SNI_EXTENSION_NAME;
                }
                break;
            case ParserState::SNI_EXTENSION_NAME:
                if (!sni)
                {
                    sni = std::unique_ptr<uint8_t>(new uint8_t[sniData.hostNameLength]);
                }

                if (accept(sni.get(), sniData.hostNameLength))
                {
                    skip(sniData.listLength - sniData.hostNameLength - 3);
                    sniCaptured = true;
                    state = ParserState::EXTENSION_TYPE;
                }
                break;
            default:
                throw std::runtime_error("unknown state");
                break;
            }
        }
    }

    void TlsParser::close()
    {
    }

    std::string TlsParser::getSNI() const
    {
        if (!hasSNI())
        {
            throw TlsParserError("SNI was not found");
        }
        return utils::sniToString(sni.get(), sniData.hostNameLength);
    }

    bool TlsParser::hasSNI() const
    {
        return sniCaptured;
    }

    bool TlsParser::hadServerHello() const
    {
        return serverHello;
    }

    TlsParser::PayloadLengthType TlsParser::getTlsPayloadLength() const {
        return tlsPayloadLength;
    }

    bool TlsParser::accept(uint8_t *data, size_t size)
    {
        size -= acceptOffset;

        if (feedOffset + size >= feedSize)
        {
            size_t copiedSize = feedSize - feedOffset;
            memcpy(reinterpret_cast<void *>(data + acceptOffset), feedData + feedOffset, copiedSize);
            feedOffset = feedSize;
            acceptOffset = copiedSize;
            return false;
        }
        memcpy(data + acceptOffset, feedData + feedOffset, size);
        feedOffset += size;
        acceptOffset = 0;
        return true;
    }

    bool TlsParser::accept(uint8_t &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(uint16_t &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(uint32_t &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(enum ContentType &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(struct ProtocolVersion &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(enum HandshakeType &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(enum tls::handshake::ExtensionType &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }

    bool TlsParser::accept(enum tls::handshake::NameType &variable)
    {
        return accept(reinterpret_cast<uint8_t *>(&variable), sizeof(variable));
    }
} // namespace tls::parser
