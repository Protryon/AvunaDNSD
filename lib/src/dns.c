//
// Created by p on 4/9/19.
//

#include <avuna/dns.h>
#include <avuna/pmem.h>
#include <string.h>
#include <netinet/in.h>


// TODO: remove dnsd related metadata from the structs

char* dns_parse_domain(struct mempool* pool, uint8_t* data, size_t* dom_offset, size_t len) {
    size_t i = *dom_offset;
    char* dom = pmalloc(pool, 16);
    dom[0] = 0;
    size_t dom_cap = 16;
    size_t dom_index = 0;
    int finished = 0;
    uint8_t c;
    while (i < len && (c = data[i]) > 0) {
        i++;
        if (!finished) *dom_offset = i;
        if ((c & 0xC0) == 0xC0) { // compressed
            uint16_t pointer = 0;
            pointer = (uint16_t) ((i & 0x3F) << 8);
            if (i + 1 < len) pointer |= data[i + 1];
            i = pointer;
            finished = 1;
        } else if ((c & 0x80) == 0x80 || (c & 0x40) == 0x40) {
            // decoding error
            return NULL;
        }
        if (i >= len || i < 0) break;
        int do_resize = 0;
        while (dom_cap < c + dom_index + 2) {
            dom_cap *= 2;
            do_resize = 1;
        }
        if (do_resize) {
            dom = prealloc(pool, dom, dom_cap);
        }
        memcpy(dom + dom_index, data + i, c);
        dom[dom_index + c] = '.';
        dom[dom_index + c + 1] = 0;
        dom_index += c + 1;
        i += c;
        if (!finished) *dom_offset = i;
    }
    if (!finished) (*dom_offset)++; // account for ending
    dom[dom_index - 1] = 0;
    return dom;
}

int dns_question_parse(struct dns_question* question, struct mempool* pool, uint8_t* buf, size_t* parse_i, ssize_t length) {
    question->domain = dns_parse_domain(pool, buf, parse_i, (size_t) length);
    if (!question->domain || length - *parse_i < 4) {
        return 1;
    }
    uint16_t* buf16 = (uint16_t*) (buf + *parse_i);
    question->type = htons(*buf16);
    *parse_i += 2;
    buf16 = (uint16_t*) (buf + *parse_i);
    question->class = htons(*buf16);
    *parse_i += 2;
    if (question->class != 1) {
        return 1; // class invalid
    }
    return 0;
}

// TODO: read data domains
int dns_record_parse(struct dns_record* record, struct mempool* pool, uint8_t* buf, size_t* parse_i, ssize_t length) {
    record->domain = dns_parse_domain(pool, buf, parse_i, (size_t) length);
    if (!record->domain || length - *parse_i < 10) {
        return 1;
    }
    uint16_t* buf16 = (uint16_t*) (buf + *parse_i);
    record->type = htons(*buf16);
    *parse_i += 2;
    buf16 = (uint16_t*) (buf + *parse_i);
    record->class = htons(*buf16);
    *parse_i += 2;
    uint32_t* buf32 = (uint32_t*) (buf + *parse_i);
    record->ttl = htonl(*buf32);
    *parse_i += 4;
    buf16 = (uint16_t*) (buf + *parse_i);
    record->rdlength = htons(*buf16);
    *parse_i += 2;
    if (record->rdlength > 1024) {
        record->rdlength = 1024; // hard cap
    }
    if (length - (ssize_t) *parse_i < (ssize_t) record->rdlength) {
        return 1;
    }
    record->data.data = pmalloc(pool, record->rdlength);
    memcpy(record->data.data, buf + *parse_i, record->rdlength);
    *parse_i += record->rdlength;
    return 0;
}


void dns_serialize_domain(int compress, char* domain, uint8_t* buf, size_t buf_completed_index, size_t buffer_capacity, size_t* out_index) {
    size_t domain_length = strlen(domain); // TODO: partial domain compression ie ruby.example.com compress to ruby.blah.
    if (domain_length + 2 + *out_index > buffer_capacity) {
        return;
    }
    if (compress) {
        size_t dl = strlen(domain) + 1;
        size_t mlx = 0;
        size_t mi = 0;
        for (size_t x = 1; x < (buf_completed_index < 16384 ? buf_completed_index : 16384); x++) {
            if (buf[x] == domain[mlx] || domain[mlx] == '.') {
                if (mi == 0) mi = x;
                mlx++;
                if (mlx == dl) {
                    break;
                }
            } else {
                mlx = 0;
                mi = 0;
            }
        }
        if (mlx != dl) mi = 0;
        if (mi > 0) {
            mi--;
            buf[*out_index] = 0xC0 | ((mi & 0x3F00) >> 8);
            (*out_index)++;
            buf[*out_index] = mi & 0xFF;
            (*out_index)++;
            return;
        }
    }
    unsigned char* lb = buf + *out_index;
    *lb = 0;
    (*out_index)++;
    for (size_t i = 0; i < domain_length; i++) {
        if (domain[i] == '.') {
            // domain should be something like .com\0 or .example.com\0
            if (compress) {
                size_t dl = strlen(domain + i);
                size_t mlx = 0;
                size_t mi = 0;
                for (size_t x = 1; x < (buf_completed_index < 16384 ? buf_completed_index : 16384); x++) {
                    if (buf[x] == domain[mlx + i] || domain[mlx + i] == '.') {
                        if (mi == 0) mi = x;
                        mlx++;
                        if (mlx == dl) {
                            break;
                        }
                    } else {
                        mlx = 0;
                        mi = 0;
                    }
                }
                if (mlx != dl) mi = 0;
                if (mi > 0) {
                    buf[*out_index] = 0xC0 | ((mi & 0x3F00) >> 8);
                    (*out_index)++;
                    buf[*out_index] = mi & 0xFF;
                    (*out_index)++;
                    return;
                }
            }
            lb = buf + *out_index;
            *lb = 0;
        } else {
            (*lb)++;
            if (*lb >= 63) {
                lb = buf + *out_index;
                *lb = 0;
            } else buf[*out_index] = domain[i];
        }
        (*out_index)++;
    }
    buf[(*out_index)++] = 0;
}

struct dns_query* dns_parse(struct mempool* pool, uint8_t* buf, ssize_t length) {
    if (length < 12) return NULL;
    struct dns_query* query = pcalloc(pool, sizeof(struct dns_query));
    memcpy(&query->header, buf, sizeof(struct dns_header));
    query->header.qdcount = (uint16_t) ((query->header.qdcount >> 8) | ((query->header.qdcount & 0xff) << 8));
    query->header.ancount = (uint16_t) ((query->header.ancount >> 8) | ((query->header.ancount & 0xff) << 8));
    query->header.nscount = (uint16_t) ((query->header.nscount >> 8) | ((query->header.nscount & 0xff) << 8));
    query->header.arcount = (uint16_t) ((query->header.arcount >> 8) | ((query->header.arcount & 0xff) << 8));

    query->questions = list_new(query->header.qdcount, pool);
    size_t parse_i = 12;
    for (int i = 0; i < query->header.qdcount; ++i) {
        struct dns_question* question = pcalloc(pool, sizeof(struct dns_question));
        if (dns_question_parse(question, pool, buf, &parse_i, length)) {
            return NULL;
        }
        list_append(query->questions, question);
    }
    query->answers = list_new(query->header.ancount, pool);
    for (int i = 0; i < query->header.ancount; ++i) {
        struct dns_record* record = pcalloc(pool, sizeof(struct dns_record));
        if (dns_record_parse(record, pool, buf, &parse_i, length)) {
            return NULL;
        }
        list_append(query->answers, record);
    }
    query->nameservers = list_new(query->header.nscount, pool);
    for (int i = 0; i < query->header.nscount; ++i) {
        struct dns_record* record = pcalloc(pool, sizeof(struct dns_record));
        if (dns_record_parse(record, pool, buf, &parse_i, length)) {
            return NULL;
        }
        list_append(query->answers, record);
    }
    query->additional_answers = list_new(query->header.arcount, pool);
    for (int i = 0; i < query->header.arcount; ++i) {
        struct dns_record* record = pcalloc(pool, sizeof(struct dns_record));
        if (dns_record_parse(record, pool, buf, &parse_i, length)) {
            return NULL;
        }
        list_append(query->answers, record);
    }
    return query;
}

int dns_question_serialize(struct dns_question* question, struct mempool* pool, uint8_t** buf, size_t* buf_i, size_t* buf_cap) {
    size_t needed_capacity = strlen(question->domain) + 2 + 4;
    int resized = 0;
    while (*buf_cap - *buf_i < needed_capacity) {
        *buf_cap *= 2;
        resized = 1;
    }
    if (resized) {
        *buf = prealloc(pool, *buf, *buf_cap);
    }
    dns_serialize_domain(1, question->domain, *buf, *buf_i, *buf_cap, buf_i);
    uint16_t type = htons(question->type);
    memcpy(*buf + *buf_i, &type, 2);
    *buf_i += 2;
    uint16_t class = htons(question->class);
    memcpy(*buf + *buf_i, &class, 2);
    *buf_i += 2;
    return 0;
}

void dns_ensure_capacity(struct mempool* pool, uint8_t** buf, size_t* buf_i, size_t* buf_cap, size_t needed_capacity) {
    int resized = 0;
    while (*buf_cap - *buf_i < needed_capacity) {
        *buf_cap *= 2;
        resized = 1;
    }
    if (resized) {
        *buf = prealloc(pool, *buf, *buf_cap);
    }

}

int dns_record_serialize(struct dns_record* record, struct mempool* pool, uint8_t** buf, size_t* buf_i, size_t* buf_cap) {
    size_t needed_capacity = strlen(record->domain) + 2 + 10 + record->rdlength;
    dns_ensure_capacity(pool, buf, buf_i, buf_cap, needed_capacity);
    dns_serialize_domain(1, record->domain, *buf, *buf_i, *buf_cap, buf_i);
    uint16_t type = htons(record->type);
    memcpy(*buf + *buf_i, &type, 2);
    *buf_i += 2;
    uint16_t class = htons(record->class);
    memcpy(*buf + *buf_i, &class, 2);
    *buf_i += 2;
    uint32_t ttl = htonl(record->ttl);
    memcpy(*buf + *buf_i, &ttl, 4);
    *buf_i += 4;
    uint16_t rd_length = htons(record->rdlength);
    memcpy(*buf + *buf_i, &rd_length, 2);
    //
    size_t rdlength_index = *buf_i;
    *buf_i += 2;
    size_t pre_data_index = *buf_i;
    if (record->type == DNS_SOA) {
        needed_capacity += strlen(record->data.soa.mname) + strlen(record->data.soa.rname) + 20;
        dns_ensure_capacity(pool, buf, buf_i, buf_cap, needed_capacity);

        dns_serialize_domain(1, record->data.soa.mname, *buf, *buf_i, *buf_cap, buf_i);
        dns_serialize_domain(1, record->data.soa.rname, *buf, *buf_i, *buf_cap, buf_i);
        uint32_t temp = htonl(record->data.soa.serial);
        memcpy(*buf + *buf_i, &temp, 4);
        *buf_i += 4;
        temp = htonl(record->data.soa.refresh);
        memcpy(*buf + *buf_i, &temp, 4);
        *buf_i += 4;
        temp = htonl(record->data.soa.retry);
        memcpy(*buf + *buf_i, &temp, 4);
        *buf_i += 4;
        temp = htonl(record->data.soa.expire);
        memcpy(*buf + *buf_i, &temp, 4);
        *buf_i += 4;
        temp = htonl(record->data.soa.minimum);
        memcpy(*buf + *buf_i, &temp, 4);
        *buf_i += 4;
    } else if (record->type == DNS_NS || record->type == DNS_CNAME || record->type == DNS_MX || record->type == DNS_DNAME || record->type == DNS_PTR) {
        needed_capacity += strlen(record->data.appended_domain.domain);
        dns_ensure_capacity(pool, buf, buf_i, buf_cap, needed_capacity);
        memcpy(*buf + *buf_i, record->data.appended_domain.data, record->rdlength);
        *buf_i += record->rdlength;
        dns_serialize_domain(1, record->data.appended_domain.domain, *buf, *buf_i, *buf_cap, buf_i);
    } else {
        memcpy(*buf + *buf_i, record->data.data, record->rdlength);
        *buf_i += record->rdlength;
    }
    uint16_t rdlength = htons((uint16_t) (*buf_i - pre_data_index));
    memcpy(*buf + rdlength_index, &rdlength, 2);
    return 0;
}

ssize_t dns_serialize(struct mempool* pool, struct dns_query* query, uint8_t** out_buf, int is_udp) {
    uint8_t* buf = *out_buf = pmalloc(pool, 32);
    size_t buf_i = 0;
    size_t buf_cap = 32;
    memcpy(buf, &query->header, 12);
    struct dns_header* internal_header = (struct dns_header*) buf;
    internal_header->qdcount = (uint16_t) ((internal_header->qdcount >> 8) | ((internal_header->qdcount & 0xff) << 8));
    internal_header->ancount = (uint16_t) ((internal_header->ancount >> 8) | ((internal_header->ancount & 0xff) << 8));
    internal_header->nscount = (uint16_t) ((internal_header->nscount >> 8) | ((internal_header->nscount & 0xff) << 8));
    internal_header->arcount = (uint16_t) ((internal_header->arcount >> 8) | ((internal_header->arcount & 0xff) << 8));
    buf_i += 12;
    for (int i = 0; i < query->header.qdcount; ++i) {
        if (dns_question_serialize(query->questions->data[i], pool, &buf, &buf_i, &buf_cap)) {
            return -1;
        }
    }
    for (int i = 0; i < query->header.ancount; ++i) {
        if (dns_record_serialize(query->answers->data[i], pool, &buf, &buf_i, &buf_cap)) {
            return -1;
        }
    }
    for (int i = 0; i < query->header.nscount; ++i) {
        if (dns_record_serialize(query->nameservers->data[i], pool, &buf, &buf_i, &buf_cap)) {
            return -1;
        }
    }
    for (int i = 0; i < query->header.arcount; ++i) {
        if (dns_record_serialize(query->additional_answers->data[i], pool, &buf, &buf_i, &buf_cap)) {
            return -1;
        }
    }

    if (is_udp && buf_i > 512) {
        buf_i = 512;
        internal_header->tc = 1;
        memcpy(buf, &query->header, 12);
    }
    *out_buf = buf;
    return buf_i;
}
