//
// Created by p on 4/9/19.
//

#ifndef AVUNA_DNSD_DNS_H
#define AVUNA_DNSD_DNS_H

#include <avuna/pmem.h>
#include <stdint.h>

#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_PTR 12
#define DNS_MX 15
#define DNS_TXT 16
#define DNS_RP 17
#define DNS_AAAA 28
#define DNS_SRV 33
#define DNS_CERT 37
#define DNS_DNAME 39
#define DNS_SSHFP 44
#define DNS_IPSECKEY 45
#define DNS_DHCID 49
#define DNS_TLSA 52
#define DNS_STAR 255
#define DNS_CAA 257

struct dns_header {
    uint16_t id;
    uint8_t rd :1;
    uint8_t tc :1;
    uint8_t aa :1;
    uint8_t opcode :4;
    uint8_t QR :1;
    uint8_t rcode :4;
    uint8_t z :3;
    uint8_t ra :1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

struct dns_question {
    // dns data
    char* domain;
    uint16_t type;
    uint16_t class;
    // book keeping
    int has_responded_to;
};

struct dns_record {
    // dns data
    char* domain;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength; // only fill out for static data fields, otherwise increased during encoding
    union {
        struct {
            uint8_t* data;
            char* domain;
        } appended_domain;
        uint8_t* data;
        struct {
            char* mname;
            char* rname;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t minimum;
        } soa;
    } data;
    // book keeping
    char* description;
    struct dns_question* in_response_to;
};

struct dns_query {
    struct dns_header header;
    struct list* questions;
    struct list* answers;
    struct list* nameservers;
    struct list* additional_answers;
};


char* dns_parse_domain(struct mempool* pool, uint8_t* data, size_t* dom_offset, size_t len);

int dns_question_parse(struct dns_question* question, struct mempool* pool, uint8_t* buf, size_t* parse_i, ssize_t length);

int dns_record_parse(struct dns_record* record, struct mempool* pool, uint8_t* buf, size_t* parse_i, ssize_t length);

void dns_serialize_domain(int compress, char* domain, uint8_t* buf, size_t buf_completed_index, size_t buffer_capacity, size_t* out_index);

struct dns_query* dns_parse(struct mempool* pool, uint8_t* buf, ssize_t length);

int dns_question_serialize(struct dns_question* question, struct mempool* pool, uint8_t** buf, size_t* buf_i, size_t* buf_cap);

int dns_record_serialize(struct dns_record* record, struct mempool* pool, uint8_t** buf, size_t* buf_i, size_t* buf_cap);

ssize_t dns_serialize(struct mempool* pool, struct dns_query* query, uint8_t** out_buf, int is_udp);

#endif //AVUNA_DNSD_DNS_H
