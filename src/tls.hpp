#pragma once
#include <cstdint>
#include <string>
#include <netinet/in.h>
#include <stdexcept>

// https://tools.ietf.org/html/rfc5246
namespace tls
{
    enum ConnectionEnd : uint8_t
    {
        SERVER,
        CLIENT
    };

    enum PRFAlgorithm : uint8_t
    {
        tls_prf_sha256
    };

    enum BulkCipherAlgorithm : uint8_t
    {
        NO_CIPHER,
        RC4,
        THREE_DES,
        AES
    };

    enum CipherType : uint8_t
    {
        STREAM,
        BLOCK,
        AEAD
    };

    enum MACAlgorithm : uint8_t
    {
        NULL_ALGORITHM,
        HMAC_MD5,
        HMAC_SHA1,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512
    };

#define COMPRESSION_METHOD_SIZE (1)

    enum CompressionMethod : uint8_t
    {
        NONE_COMMPRESION = 0,
    };

    enum ContentType : uint8_t
    {
        CHANGE_CIPHER_SPEC = 20,
        ALERT = 21,
        HANDSHAKE = 22,
        APPLICATION_DATA = 23,
    };

    struct SecurityParameters
    {
        enum ConnectionEnd entity;
        enum PRFAlgorithm prf_algorithm;
        enum BulkCipherAlgorithm bulk_cipher_algorithm;
        enum CipherType cipher_type;
        uint8_t enc_key_length;
        uint8_t block_length;
        uint8_t fixed_iv_length;
        uint8_t record_iv_length;
        enum MACAlgorithm mac_algorithm;
        uint8_t mac_length;
        uint8_t mac_key_length;
        enum CompressionMethod compression_algorithm;
        uint8_t master_secret[48];
        uint8_t client_random[32];
        uint8_t server_random[32];
    };

#define PROTOCOL_VERSION_SIZE (2)

    struct ProtocolVersion
    {
        uint8_t major;
        uint8_t minor;
    };

#define TLSPLAINTEXT_SIZE (5)

    struct TLSPlaintext
    {
        enum ContentType type;
        struct ProtocolVersion version;
        uint16_t length;
        // opaque fragment[TLSPlaintext.length]; data
    };

    struct ChangeCipherSpec
    {
        uint8_t CHANGE_CIPHER_SPEC; // should be only 1
    };

    enum AlertLevel : uint8_t
    {
        WARNING = 1,
        FATAL = 2
    };

    enum AlertDescription : uint8_t
    {
        CLOSE_NOTIFY = 0,
        UNEXPECTED_MESSAGE = 10,
        BAD_RECORD_MAC = 20,
        DECRYPTION_FAILED_RESERVED = 21,
        RECORD_OVERFLOW = 22,
        DECOMPRESSION_FAILURE = 30,
        HANDSHAKE_FAILURE = 40,
        NO_CERTIFICATE_RESERVED = 41,
        BAD_CERTIFICATE = 42,
        UNSUPPORTED_CERTIFICATE = 43,
        CERTIFICATE_REVOKED = 44,
        CERTIFICATE_EXPIRED = 45,
        CERTIFICATE_UNKNOWN = 46,
        ILLEGAL_PARAMETER = 47,
        UNKNOWN_CA = 48,
        ACCESS_DENIED = 49,
        DECODE_ERROR = 50,
        DECRYPT_ERROR = 51,
        EXPORT_RESTRICTION_RESERVED = 60,
        PROTOCOL_VERSION = 70,
        INSUFFICIENT_SECURITY = 71,
        INTERNAL_ERROR = 80,
        USER_CANCELED = 90,
        NO_RENEGOTIATION = 100,
        UNSUPPORTED_EXTENSION = 110,
    };

    struct Alert
    {
        AlertLevel level;
        AlertDescription description;
    };

    enum HandshakeType : uint8_t
    {
        HELLO_REQUEST = 0,
        CLIENT_HELLO = 1,
        SERVER_HELLO = 2,
        CERTIFICATE = 11,
        SERVER_KEY_EXCHANGE = 12,
        CERTIFICATE_REQUEST = 13,
        SERVER_HELLO_DONE = 14,
        CERTIFICATE_VERIFY = 15,
        CLIENT_KEY_EXCHANGE = 16,
        FINISHED = 20
    };

#define HANDSHAKE_SIZE (4)

    struct Handshake
    {
        HandshakeType messageType; /* handshake type */
        uint32_t length : 24;      /* bytes in message */
                                   //   select (HandshakeType) {
                                   //       case hello_request:       HelloRequest;
                                   //       case client_hello:        ClientHello;
                                   //       case server_hello:        ServerHello;
                                   //       case certificate:         Certificate;
                                   //       case server_key_exchange: ServerKeyExchange;
                                   //       case certificate_request: CertificateRequest;
                                   //       case server_hello_done:   ServerHelloDone;
                                   //       case certificate_verify:  CertificateVerify;
                                   //       case client_key_exchange: ClientKeyExchange;
                                   //       case finished:            Finished;
                                   //   } body;
    };

#define RANDOM_SIZE (32)

    struct Random
    {
        uint32_t gmt_unix_time;
        uint8_t random_bytes[28];
    };

    // Utility class

    class TlsError : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };
    class TlsUnsupportedVersion : public TlsError
    {
        using TlsError::TlsError;
    };
    class TlsInvalidContentType : public TlsError
    {
        using TlsError::TlsError;
    };
    class TlsPayloadError : public TlsError
    {
        using TlsError::TlsError;
    };
    class NotTlsSession : public TlsError
    {
        using TlsError::TlsError;
    };

    class RecordProtocol
    {
    private:
        std::string version;
        enum ContentType type;
        decltype(TLSPlaintext::length) length;

    public:
        RecordProtocol();
        std::string getVersion();
        enum ContentType getContentType();
        uint16_t getRecordProtocolLength();
        void setVersion(ProtocolVersion version);
        void setContentType(enum ContentType type);
        void setRecordProtocolLength(decltype(TLSPlaintext::length) length);

        static std::string parseVersion(ProtocolVersion version)
        {
            if (version.major == 3)
            {
                if (version.minor == 0)
                {
                    return "SSL 3.0";
                }

                return "TLS 1." + std::to_string(version.minor - 1);
            }
            else
            {
                throw TlsUnsupportedVersion("SSL version not supported. " + std::to_string(version.major) + "." + std::to_string(version.minor));
            }
        }
    };
} // namespace tls
