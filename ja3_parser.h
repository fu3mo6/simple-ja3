#ifndef JA3_PARSER_H
#define JA3_PARSER_H

#define JA3_MAX_LEN 4096
typedef struct ja3_result_s {
    char ja3[JA3_MAX_LEN];
    size_t len;
} ja3_result_t;

char* clienthello_parse_ja3(const u_int8_t *pkt, u_int16_t len, size_t caplen);
char* serverhello_parse_ja3s(const u_int8_t *pkt, u_int16_t len, size_t caplen);

#endif