#ifndef TLS_STANDARD_H
#define TLS_STANDARD_H

// reference: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tls-utils.h
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

typedef enum {
    SSL_ID_CHG_CIPHER_SPEC         = 0x14,
    SSL_ID_ALERT                   = 0x15,
    SSL_ID_HANDSHAKE               = 0x16,
    SSL_ID_APP_DATA                = 0x17,
    SSL_ID_HEARTBEAT               = 0x18
} ContentType;

typedef enum {
    SSL_HND_HELLO_REQUEST          = 0,
    SSL_HND_CLIENT_HELLO           = 1,
    SSL_HND_SERVER_HELLO           = 2,
    SSL_HND_HELLO_VERIFY_REQUEST   = 3,
    SSL_HND_NEWSESSION_TICKET      = 4,
    SSL_HND_END_OF_EARLY_DATA      = 5,
    SSL_HND_HELLO_RETRY_REQUEST    = 6,
    SSL_HND_ENCRYPTED_EXTENSIONS   = 8,
    SSL_HND_CERTIFICATE            = 11,
    SSL_HND_SERVER_KEY_EXCHG       = 12,
    SSL_HND_CERT_REQUEST           = 13,
    SSL_HND_SVR_HELLO_DONE         = 14,
    SSL_HND_CERT_VERIFY            = 15,
    SSL_HND_CLIENT_KEY_EXCHG       = 16,
    SSL_HND_FINISHED               = 20,
    SSL_HND_CERT_URL               = 21,
    SSL_HND_CERT_STATUS            = 22,
    SSL_HND_SUPPLEMENTAL_DATA      = 23,
    SSL_HND_KEY_UPDATE             = 24,
    SSL_HND_COMPRESSED_CERTIFICATE = 25,
    /* Encrypted Extensions was NextProtocol in draft-agl-tls-nextprotoneg-03
     * and changed in draft 04. Not to be confused with TLS 1.3 EE. */
    SSL_HND_ENCRYPTED_EXTS         = 67
} HandshakeType;

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define SSL_HND_HELLO_EXT_SERVER_NAME                   0
#define SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH           1
#define SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL        2
#define SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS               3
#define SSL_HND_HELLO_EXT_TRUNCATED_HMAC                4
#define SSL_HND_HELLO_EXT_STATUS_REQUEST                5
#define SSL_HND_HELLO_EXT_USER_MAPPING                  6
#define SSL_HND_HELLO_EXT_CLIENT_AUTHZ                  7
#define SSL_HND_HELLO_EXT_SERVER_AUTHZ                  8
#define SSL_HND_HELLO_EXT_CERT_TYPE                     9
#define SSL_HND_HELLO_EXT_SUPPORTED_GROUPS              10 /* renamed from "elliptic_curves" (RFC 7919 / TLS 1.3) */
#define SSL_HND_HELLO_EXT_EC_POINT_FORMATS              11
#define SSL_HND_HELLO_EXT_SRP                           12
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS          13
#define SSL_HND_HELLO_EXT_USE_SRTP                      14
#define SSL_HND_HELLO_EXT_HEARTBEAT                     15
#define SSL_HND_HELLO_EXT_ALPN                          16
#define SSL_HND_HELLO_EXT_STATUS_REQUEST_V2             17
#define SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP  18
#define SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE              19
#define SSL_HND_HELLO_EXT_SERVER_CERT_TYPE              20
#define SSL_HND_HELLO_EXT_PADDING                       21
#define SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC              22
#define SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET        23
#define SSL_HND_HELLO_EXT_TOKEN_BINDING                 24
#define SSL_HND_HELLO_EXT_CACHED_INFO                   25
#define SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE          27
#define SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT             28
/* 26-34  Unassigned*/
#define SSL_HND_HELLO_EXT_SESSION_TICKET_TLS            35
/* RFC 8446 (TLS 1.3) */
#define SSL_HND_HELLO_EXT_KEY_SHARE_OLD                 40 /* draft-ietf-tls-tls13-22 (removed in -23) */
#define SSL_HND_HELLO_EXT_PRE_SHARED_KEY                41
#define SSL_HND_HELLO_EXT_EARLY_DATA                    42
#define SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS            43
#define SSL_HND_HELLO_EXT_COOKIE                        44
#define SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES        45
#define SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO        46 /* draft-ietf-tls-tls13-18 (removed in -19) */
#define SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES       47
#define SSL_HND_HELLO_EXT_OID_FILTERS                   48
#define SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH           49
#define SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT     50
#define SSL_HND_HELLO_EXT_KEY_SHARE                     51
#define SSL_HND_HELLO_EXT_GREASE_0A0A                   2570
#define SSL_HND_HELLO_EXT_GREASE_1A1A                   6682
#define SSL_HND_HELLO_EXT_GREASE_2A2A                   10794
#define SSL_HND_HELLO_EXT_NPN                           13172 /* 0x3374 */
#define SSL_HND_HELLO_EXT_GREASE_3A3A                   14906
#define SSL_HND_HELLO_EXT_GREASE_4A4A                   19018
#define SSL_HND_HELLO_EXT_GREASE_5A5A                   23130
#define SSL_HND_HELLO_EXT_GREASE_6A6A                   27242
#define SSL_HND_HELLO_EXT_CHANNEL_ID_OLD                30031 /* 0x754f */
#define SSL_HND_HELLO_EXT_CHANNEL_ID                    30032 /* 0x7550 */
#define SSL_HND_HELLO_EXT_GREASE_7A7A                   31354
#define SSL_HND_HELLO_EXT_GREASE_8A8A                   35466
#define SSL_HND_HELLO_EXT_GREASE_9A9A                   39578
#define SSL_HND_HELLO_EXT_GREASE_AAAA                   43690
#define SSL_HND_HELLO_EXT_GREASE_BABA                   47802
#define SSL_HND_HELLO_EXT_GREASE_CACA                   51914
#define SSL_HND_HELLO_EXT_GREASE_DADA                   56026
#define SSL_HND_HELLO_EXT_GREASE_EAEA                   60138
#define SSL_HND_HELLO_EXT_GREASE_FAFA                   64250
#define SSL_HND_HELLO_EXT_RENEGOTIATION_INFO            65281 /* 0xFF01 */
#define SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS     65445 /* 0xffa5 draft-ietf-quic-tls-13 */
#define SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME         65486 /* 0xffce draft-ietf-tls-esni-01 */

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd

struct TLS_RECORD
{
    u_int8_t ctype; // 1-byte: content type
    u_int16_t ver; // 2-byte: version
    u_int16_t len; // 2-byte: length
} __attribute__((packed));;

struct TLS_HANDSHAKE_HEADER
{
    u_int8_t htype; // 1-byte: handshake type
    u_int8_t len[3]; // 3-byte: length
} __attribute__((packed));;

struct TLS_HELLO_HEADER
{
    u_int16_t ver; // 2-byte: version
    u_int8_t rand[32];
    // Session ID len (1-byte)
    // Session ID
    // Cipher Suites len (2-byte)
    // Cipher SUites
    // Compression Methods len (1-byte)
    // Compression Methods
    // Extensions len (2-byte)
    // Extensions
} __attribute__((packed));;

struct TLS_EXTENSION_HEADER
{
    u_int16_t type; // 2-byte: type
    u_int16_t len; // 2-byte: length
} __attribute__((packed));;

#endif