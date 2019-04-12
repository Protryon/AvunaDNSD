//
// Created by p on 4/9/19.
//

#ifndef AVUNA_DNSD_DNS_RESOLVER_H
#define AVUNA_DNSD_DNS_RESOLVER_H

#include "../lib/include/avuna/dns.h"
#include "zone.h"
#include <avuna/pmem.h>
#include <avuna/list.h>

void dns_resolve(uint16_t type, char* domain, struct zone* zone, struct list* records, struct list* additional_records, struct mempool* pool);

void dns_respond_query(struct mempool* pool, struct dns_query* query, struct zone* zone);

void dns_report(struct sockaddr* addr, struct dns_query* query, struct logsess* log);

#endif //AVUNA_DNSD_DNS_RESOLVER_H
