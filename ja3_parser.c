
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> /* close */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tls_standard.h"
#include "ja3_parser.h"

#define MAX_U16_LEN 5 // 0xffff = 65535 -> length = 5
#define MAX_U8_LEN 2 // 0xff = 64 -> length = 2

#define offset_update(offset, plus, caplen) \
	do {    \
        offset += plus; \
		if (offset > caplen) { \
            goto offset_err; \
        } \
	} while (0);

static int ja3_add_u8(ja3_result_t *result, u_int8_t input)
{
    if(result->len + MAX_U8_LEN >= JA3_MAX_LEN)
        return 1;
    else {
        result->len += snprintf(result->ja3 + result->len, JA3_MAX_LEN-result->len, "%d", input);
        return 0;
    }
}

static int ja3_add_u16(ja3_result_t *result, u_int16_t input)
{
    if(result->len + MAX_U16_LEN >= JA3_MAX_LEN)
        return 1;
    else {
        result->len += snprintf(result->ja3 + result->len, JA3_MAX_LEN-result->len, "%d", input);
        return 0;
    }
}

static int ja3_add_str(ja3_result_t *result, const char* input)
{
    if(result->len + strlen(input) >= JA3_MAX_LEN)
        return 1;
    else {
        result->len += snprintf(result->ja3 + result->len, JA3_MAX_LEN-result->len, "%s", input);
        return 0;
    }
}

static int ntohs_3b(const u_int8_t* input)
{
    return (input[0] << 16) | (input[1] <<  8) | (input[2] <<  0);
}

static int ja3_grease_table(u_int16_t input){
    switch(input)
    {
    case SSL_HND_HELLO_EXT_GREASE_0A0A:
    case SSL_HND_HELLO_EXT_GREASE_1A1A:
    case SSL_HND_HELLO_EXT_GREASE_2A2A:
    case SSL_HND_HELLO_EXT_GREASE_3A3A:
    case SSL_HND_HELLO_EXT_GREASE_4A4A:
    case SSL_HND_HELLO_EXT_GREASE_5A5A:
    case SSL_HND_HELLO_EXT_GREASE_6A6A:
    case SSL_HND_HELLO_EXT_GREASE_7A7A:
    case SSL_HND_HELLO_EXT_GREASE_8A8A:
    case SSL_HND_HELLO_EXT_GREASE_9A9A:
    case SSL_HND_HELLO_EXT_GREASE_AAAA:
    case SSL_HND_HELLO_EXT_GREASE_BABA:
    case SSL_HND_HELLO_EXT_GREASE_CACA:
    case SSL_HND_HELLO_EXT_GREASE_DADA:
    case SSL_HND_HELLO_EXT_GREASE_EAEA:
    case SSL_HND_HELLO_EXT_GREASE_FAFA:
        return 1;
    default:
        return 0;
    }
}

static int ja3_append_hver(ja3_result_t *result, const struct TLS_HELLO_HEADER *tls_hello)
{
    return ja3_add_u16(result, ntohs(tls_hello->ver));
}

static int ja3_append_u16(ja3_result_t *result, const u_int8_t *ptr, u_int16_t len)
{
    int i = 0, offset = 0;
    u_int16_t val = 0;
    int isFirst = 1;
    for(i=0; i<len/2; i++){
        val = *(u_int16_t*)(ptr+offset);
        val = ntohs(val);
        offset += 2;
        if(!ja3_grease_table(val)){
            if(isFirst == 1)
                isFirst = 0;
            else if(ja3_add_str(result, "-"))
                return 1;
                    
            if(ja3_add_u16(result, val))
                return 1;
        }
    }
    return 0;
}

static int ja3_append_u8(ja3_result_t *result, const u_int8_t *ptr, u_int16_t len)
{
    int i = 0, offset = 0;
    u_int8_t val = 0;
    int isFirst = 1;
    for(i=0; i<len; i++){
        val = *(ptr+offset);
        offset ++;
        if(isFirst == 1)
            isFirst = 0;
        else if(ja3_add_str(result, "-"))
            return 1;

        if(ja3_add_u8(result, val))
            return 1;
    }
    return 0;
}

static int ja3_append_ext_sup_group(ja3_result_t *result, const u_int8_t *ptr)
{
    const struct TLS_EXTENSION_HEADER *tls_ext;
    u_int16_t sup_group_len;
    int offset = 0;

    tls_ext = (const struct TLS_EXTENSION_HEADER *)(ptr);
    offset += sizeof(*tls_ext);

    sup_group_len = *(u_int16_t*)(ptr + offset);
    offset += sizeof(u_int16_t);

    return ja3_append_u16(result, ptr + offset, ntohs(sup_group_len));
}

static int ja3_append_ext_ec_point(ja3_result_t *result, const u_int8_t *ptr)
{
    const struct TLS_EXTENSION_HEADER *tls_ext;
    u_int8_t ec_point_len;
    int offset = 0;

    tls_ext = (const struct TLS_EXTENSION_HEADER *)(ptr);
    offset += sizeof(*tls_ext);

    ec_point_len = *(ptr + offset);
    offset += sizeof(u_int8_t);

    return ja3_append_u8(result, ptr + offset, ec_point_len);
}

static int ja3_append_ext(ja3_result_t *result, const u_int8_t *ext_start, size_t ext_len, int is_client)
{
    const struct TLS_EXTENSION_HEADER *tls_ext;
    u_int8_t* ext_data;
    u_int8_t *ext_supported_group = NULL;
    u_int8_t *ext_ec_point = NULL;
    int offset = 0;
    int isFirst = 1;

    while(offset < ext_len)
    {
        tls_ext = (const struct TLS_EXTENSION_HEADER *)(ext_start+offset);
        offset_update(offset, sizeof(*tls_ext), ext_len);

        ext_data = (u_int8_t*) (ext_start+offset);
        offset_update(offset, ntohs(tls_ext->len), ext_len);

        if(!ja3_grease_table(ntohs(tls_ext->type))){
            if(isFirst == 1)
                isFirst = 0;
            else if(ja3_add_str(result, "-"))
                return 1;

            if(ja3_add_u16(result, ntohs(tls_ext->type)))
                return 1;
        }

        if(ntohs(tls_ext->type) == SSL_HND_HELLO_EXT_SUPPORTED_GROUPS){
            ext_supported_group = (u_int8_t*) tls_ext;
        }
        else if(ntohs(tls_ext->type) == SSL_HND_HELLO_EXT_EC_POINT_FORMATS){
            ext_ec_point = (u_int8_t*) tls_ext;
        }        
    }

    if(is_client)
    {
        if(ja3_add_str(result, ","))
            return 1;
        if(ext_supported_group){
            if(ja3_append_ext_sup_group(result, ext_supported_group))
                return 1;
        }
        if(ja3_add_str(result, ","))
            return 1;
        if(ext_ec_point){
            if(ja3_append_ext_ec_point(result, ext_ec_point))
                return 1;
        }
    }
    return 0;

offset_err:
    return 1;
}

char* clienthello_parse_ja3(const u_int8_t *pkt, u_int16_t len, size_t caplen)
{
    const struct TLS_RECORD *tls_rec;
    const struct TLS_HANDSHAKE_HEADER *tls_handshake;
    const struct TLS_HELLO_HEADER *tls_hello;
    u_int8_t sessid_len, comp_method_len;
    u_int16_t cipher_len, ext_len;
    u_int8_t *sessid, *cipher, *comp_method;

    int offset = 0;
    ja3_result_t result = {0};

    if(caplen < sizeof(*tls_rec))
        return NULL;

    tls_rec = (const struct TLS_RECORD *)(pkt+offset);
    offset_update(offset, sizeof(*tls_rec), caplen);

    if (tls_rec->ctype != SSL_ID_HANDSHAKE)
        return NULL;
    if ((ntohs(tls_rec->ver) & SSLV3_VERSION) != SSLV3_VERSION)
        return NULL;

    tls_handshake = (const struct TLS_HANDSHAKE_HEADER *)(pkt+offset);
    offset_update(offset, sizeof(*tls_handshake), caplen);

    if (tls_handshake->htype != SSL_HND_CLIENT_HELLO)
        return NULL;

    tls_hello = (const struct TLS_HELLO_HEADER *)(pkt+offset);
    offset_update(offset, sizeof(*tls_hello), caplen);

    sessid_len = *(pkt+offset);
    offset_update(offset, sizeof(sessid_len), caplen);
    
    if(sessid_len > 0)
    {
        sessid = (u_int8_t*)(pkt+offset); // skip: don't need session ID
        offset_update(offset, sessid_len, caplen);
    }

    cipher_len = *(u_int16_t*)(pkt+offset);
    offset_update(offset, sizeof(cipher_len), caplen);

    if(ntohs(cipher_len) > 0)
    {
        cipher = (u_int8_t*)(pkt+offset);
        offset_update(offset, ntohs(cipher_len), caplen);
    }
    
    comp_method_len = *(pkt+offset);
    offset_update(offset, sizeof(comp_method_len), caplen);

    if(comp_method_len > 0)
    {
        comp_method = (u_int8_t*)(pkt+offset); // skip: don't need compression method
        offset_update(offset, comp_method_len, caplen);
    }

    if(ja3_append_hver(&result, tls_hello))
        return NULL;
    if(ja3_add_str(&result, ","))
        return NULL;
    if(ja3_append_u16(&result, cipher, ntohs(cipher_len)))
        return NULL;
    if(ja3_add_str(&result, ","))
        return NULL;

    if(ntohs(tls_hello->ver) == SSLV3_VERSION) // skip tls extension
    {
        if(ja3_add_str(&result, ",,"))
            return NULL;
        else
            return strdup(result.ja3);
    }

    ext_len = *(u_int16_t*) (pkt+offset);
    offset_update(offset, sizeof(ext_len), caplen);
    
    if (caplen < offset + ntohs(ext_len))
        return NULL;
    if(ja3_append_ext(&result, pkt+offset, ntohs(ext_len), 1))
        return NULL;

    return strdup(result.ja3);

offset_err:
    return NULL;
}


char* serverhello_parse_ja3s(const u_int8_t *pkt, u_int16_t len, size_t caplen)
{
    const struct TLS_RECORD *tls_rec;
    const struct TLS_HANDSHAKE_HEADER *tls_handshake;
    const struct TLS_HELLO_HEADER *tls_hello;
    u_int8_t sessid_len, comp_method_len;
    u_int16_t cipher, ext_len;
    u_int8_t *sessid, *comp_method;

    int offset = 0;
    ja3_result_t result = {0};

    if(caplen < sizeof(*tls_rec))
        return NULL;

    tls_rec = (const struct TLS_RECORD *)(pkt+offset);
    offset_update(offset, sizeof(*tls_rec), caplen);

    if (tls_rec->ctype != SSL_ID_HANDSHAKE)
        return NULL;
    if ((ntohs(tls_rec->ver) & SSLV3_VERSION) != SSLV3_VERSION)
        return NULL;

    tls_handshake = (const struct TLS_HANDSHAKE_HEADER *)(pkt+offset);
    offset_update(offset, sizeof(*tls_handshake), caplen);

    if (tls_handshake->htype != SSL_HND_SERVER_HELLO)
        return NULL;

    tls_hello = (const struct TLS_HELLO_HEADER *)(pkt+offset);

    offset_update(offset, sizeof(*tls_hello), caplen);

    sessid_len = *(pkt+offset);
    offset_update(offset, sizeof(sessid_len), caplen);
    if(sessid_len > 0)
    {
        sessid = (u_int8_t*)(pkt+offset); // skip: don't need session ID
        offset_update(offset, sessid_len, caplen);
    }

    cipher = *(u_int16_t*)(pkt+offset);
    offset_update(offset, sizeof(cipher), caplen);
    
    comp_method_len = *(pkt+offset);
    offset_update(offset, sizeof(comp_method_len), caplen);
    if(comp_method_len > 0)
    {
        comp_method = (u_int8_t*)(pkt+offset); // skip: don't need compression method
        offset_update(offset, comp_method_len, caplen);
    }

    if(ja3_append_hver(&result, tls_hello))
        return NULL;
    if(ja3_add_str(&result, ","))
        return NULL;
    if(ja3_add_u16(&result, ntohs(cipher)))
        return NULL;
    if(ja3_add_str(&result, ","))
        return NULL;

    if (offset >= ntohs_3b(tls_handshake->len) + sizeof(*tls_rec) + sizeof(*tls_handshake)) // FIXME: 3 byte len
        return strdup(result.ja3); // no extension
    
    ext_len = *(u_int16_t*) (pkt+offset);
    offset_update(offset, sizeof(ext_len), caplen);
    if (caplen < offset + ntohs(ext_len))
        return NULL;

    if(ja3_append_ext(&result, pkt+offset, ntohs(ext_len), 0))
        return NULL;

    return strdup(result.ja3);

offset_err:
    return NULL;
}