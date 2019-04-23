//
// Created by p on 4/9/19.
//

#include "dns_resolver.h"
#include "../lib/include/avuna/dns.h"
#include "zone.h"
#include "version.h"
#include "globals.h"
#include <avuna/pmem.h>
#include <avuna/string.h>
#include <avuna/util.h>
#include <arpa/inet.h>

void dns_resolve(uint16_t type, char* domain, struct zone* zone, struct zone* root_zone, struct list* records, struct list* additional_records, struct mempool* pool, int depth);

void dns_prepare_additional_records(struct dns_record* record, struct zone* zone, struct list* additional_records, struct mempool* pool, int depth) {
    if (record->type == DNS_CNAME) {
        dns_resolve(1, record->data.appended_domain.domain, zone, zone, additional_records, additional_records, pool, depth + 1);
    } else if (record->type == DNS_MX) {
        dns_resolve(1, record->data.appended_domain.domain, zone, zone, additional_records, additional_records, pool, depth + 1);
    }
}

void dns_resolve(uint16_t type, char* domain, struct zone* zone, struct zone* root_zone, struct list* records, struct list* additional_records, struct mempool* pool, int depth) {
    if (depth > 16) {
        return;
    }
    ssize_t roundrobin_per = -1;
    struct list* round_robin = NULL;
    if (str_eq(domain, "version.bind") && type == DNS_TXT) {
        static char* cached_version;
        if (cached_version == NULL) {
            cached_version = pmalloc(global_pool, 2 + strlen("AvunaDNSD-" VERSION));
            cached_version[0] = 15;
            memcpy(cached_version + 1, "AvunaDNSD-" VERSION, strlen("AvunaDNSD-" VERSION));;
        }
        struct dns_record* record = pcalloc(pool, sizeof(struct dns_record));
        record->class = 1;
        record->domain = domain;
        record->data.data = (uint8_t*) cached_version;
        record->rdlength = (uint16_t) strlen(cached_version);
        record->ttl = 3600;
        record->type = DNS_TXT;
        record->description = ("AvunaDNSD-" VERSION);
        list_append(records, record);
        return;
    }
    int avoiding_type = -1;
    ITER_LIST(zone->entries) {
        struct zone_entry* entry = item;
        if (entry->type == ZONE_SUBZONE && domeq(entry->part.subzone->domain, domain, records->count == 0) && roundrobin_per < 0) {
            dns_resolve(type, domain, entry->part.subzone, root_zone, records, additional_records, pool, depth + 1);
        } else if (entry->type == ZONE_ENTRY && (entry->part.dom.record->type == type || entry->part.dom.is_psuedo_type)) {
            int extensible = avoiding_type != entry->part.dom.record->type;
            if (extensible && str_prefixes(entry->part.dom.record->domain, "~")) {
                for (size_t i = 0; i < records->count; ++i) {
                    struct dns_record* record = records->data[i];
                    if (record->type == type) {
                        extensible = 0;
                        break;
                    }
                }
            }
            if (domeq(entry->part.dom.record->domain, domain, extensible)) {
                if (entry->part.dom.is_negative) {
                    avoiding_type = entry->part.dom.record->type;
                    continue;
                }
                if (roundrobin_per >= 0) {
                    list_append(round_robin, entry);
                } else {
                    struct dns_record* record = xcopy(entry->part.dom.record, sizeof(struct dns_record), 0, pool);
                    record->domain = domain;
                    record->ttl = entry->part.dom.ttl_minimum + (entry->part.dom.ttl_maximum == entry->part.dom.ttl_minimum ? 0 : (rand() % (entry->part.dom.ttl_maximum - entry->part.dom.ttl_minimum)));
                    list_append(records, record);
                    dns_prepare_additional_records(record, root_zone, additional_records, pool, depth);
                }
            }
        } else if (entry->type == ZONE_ROUNDSTART) {
            roundrobin_per = entry->part.roundrobin.per;
            round_robin = list_new(8, pool);
        } else if (entry->type == ZONE_ROUNDSTOP) {
            if (round_robin->count <= roundrobin_per) {
                for (size_t i = 0; i < round_robin->count; ++i) {
                    struct zone_entry* round_robin_entry = round_robin->data[i];
                    struct dns_record* record = xcopy(round_robin_entry->part.dom.record, sizeof(struct dns_record), 0, pool);
                    record->domain = domain;
                    record->ttl = round_robin_entry->part.dom.ttl_minimum + (round_robin_entry->part.dom.ttl_maximum == round_robin_entry->part.dom.ttl_minimum ? 0 : (rand() % (round_robin_entry->part.dom.ttl_maximum - round_robin_entry->part.dom.ttl_minimum)));
                    list_append(records, record);
                    dns_prepare_additional_records(record, root_zone, additional_records, pool, depth);
                }
            } else {
                size_t shuffled_index = rand() % round_robin->count;
                for (size_t i = 0; i < roundrobin_per; ++i) {
                    struct zone_entry* round_robin_entry = round_robin->data[shuffled_index];
                    struct dns_record* record = xcopy(round_robin_entry->part.dom.record, sizeof(struct dns_record), 0, pool);
                    record->domain = domain;
                    record->ttl = round_robin_entry->part.dom.ttl_minimum + (round_robin_entry->part.dom.ttl_maximum == round_robin_entry->part.dom.ttl_minimum ? 0 : (rand() % (round_robin_entry->part.dom.ttl_maximum - round_robin_entry->part.dom.ttl_minimum)));
                    list_append(records, record);
                    dns_prepare_additional_records(record, root_zone, additional_records, pool, depth);
                    ++shuffled_index;
                    if (shuffled_index >= round_robin->count) {
                        shuffled_index = 0;
                    }
                }
            }
            roundrobin_per = -1;
        }
        ITER_LIST_END();
    }

    if (records->count == 0 && type == DNS_A) {
        dns_resolve(DNS_CNAME, domain, zone, root_zone, records, additional_records, pool, depth + 1);
    }
}

void dns_respond_query(struct mempool* pool, struct dns_query* query, struct zone* zone) {
    query->header.ancount = 0;
    query->header.nscount = 0;
    query->header.arcount = 0;
    if (query->header.opcode != 0) {
        query->header.rcode = 4;
        query->header.qdcount = 0;
        return;
    }

    query->header.rd = 0;
    query->header.tc = 0;
    query->header.aa = 1;
    query->header.opcode = 0;
    query->header.QR = 1;
    query->header.rcode = 0;
    query->header.z = 0;
    query->header.ra = 0;
    query->answers = list_new(query->header.qdcount + 1, pool);
    query->nameservers = list_new(0, pool);
    query->additional_answers = list_new(query->header.qdcount + 1, pool);
    size_t last_answer = 0;
    size_t last_additional_answer = 0;
    for (int i = 0; i < query->header.qdcount; i++) {
        struct dns_question* question = query->questions->data[i];
        dns_resolve(question->type, question->domain, zone, zone, query->answers, query->additional_answers, pool, 0);
        for (size_t x = last_answer; x < query->answers->count; ++x) {
            struct dns_record* record = query->answers->data[x];
            record->in_response_to = question;
            question->has_responded_to = 1;
        }
        last_answer = query->answers->count;
        for (size_t x = last_additional_answer; x < query->additional_answers->count; ++x) {
            struct dns_record* record = query->additional_answers->data[x];
            record->in_response_to = question;
            question->has_responded_to = 1;
        }
        last_additional_answer = query->additional_answers->count;
    }
    query->header.ancount = (uint16_t) query->answers->count;
    query->header.arcount = (uint16_t) query->additional_answers->count;
}

void dns_report(struct sockaddr* addr, struct dns_query* query, struct logsess* log) {
    char ip_stack_string[48];
    const char* ip_string = ip_stack_string;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sip4 = (struct sockaddr_in*) addr;
        inet_ntop(AF_INET, &sip4->sin_addr, ip_stack_string, 48);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) addr;
        if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
            inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, ip_stack_string, 48);
        } else inet_ntop(AF_INET6, &sip6->sin6_addr, ip_stack_string, 48);
    } else if (addr->sa_family == AF_LOCAL) {
        ip_string = "UNIX";
    } else {
        ip_string = "UNKNOWN";
    }

    for (size_t i = 0; i < query->answers->count; ++i) {
        struct dns_record* record = query->answers->data[i];
        acclog(log, "%s requested %s for %s, returned %s %s", ip_string, typeString(record->in_response_to->type), record->in_response_to->domain, typeString(record->type), record->description);
    }
    for (size_t i = 0; i < query->additional_answers->count; ++i) {
        struct dns_record* record = query->additional_answers->data[i];
        acclog(log, "%s requested %s for %s, returned<assume> %s %s", ip_string, typeString(record->in_response_to->type), record->in_response_to->domain, typeString(record->type), record->description);
    }
    for (size_t i = 0; i < query->questions->count; ++i) {
        struct dns_question* question = query->questions->data[i];
        if (!question->has_responded_to) {
            acclog(log, "%s requested %s for %s, returned nothing", ip_string, typeString(question->type), question->domain);
        }
    }
}
