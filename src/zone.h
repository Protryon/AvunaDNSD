/*
 * zone.h
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#ifndef ZONE_H_
#define ZONE_H_

#include "dns.h"
#include <netinet/in.h>
#include <avuna/log.h>
#include <avuna/pmem.h>

struct dns_entry {
	struct dns_record* record;
	int is_psuedo_type;
	uint32_t ttl_minimum;
	uint32_t ttl_maximum;
	int is_negative;
};

struct roundrobin {
	ssize_t per;
};

#define ZONE_SUBZONE 0
#define ZONE_ENTRY 1
#define ZONE_ROUNDSTART 2
#define ZONE_ROUNDSTOP 3

struct zone_entry {
	int type;
	union {
		struct zone* subzone;
		struct dns_entry dom;
		struct roundrobin roundrobin;
	} part;
};

struct zone {
	struct mempool* pool;
	char* domain;
	struct list* entries;
};

const char* typeString(int type);

int domeq(char* domain1, char* domain2, int extensible);

int zone_add_entry(struct zone* zone, struct zone_entry* entry);

int zone_read(struct zone* zone, char* file, char* relative_path, struct logsess* log);

void zone_parse_dns_entry(struct mempool* pool, struct logsess* log, char* file, ssize_t line_number, struct dns_entry* dns_entry, char* args[], size_t arg_count);

#endif /* ZONE_H_ */
