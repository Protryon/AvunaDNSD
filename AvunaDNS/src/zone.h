/*
 * zone.h
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#ifndef ZONE_H_
#define ZONE_H_

#include <netinet/in.h>
#include "log.h"

struct domentry {
		char* domain;
		int type;
		int pt;
		int ttlmin;
		int ttlmax;
		size_t data_len;
		void* data;
};

struct roundrobin {
		int per;
};

union zoneparts {
		struct zone* subzone;
		struct domentry dom;
		struct roundrobin rrst;
};

struct zoneentry {
		int type; // 0 = subzone, 1 = domentry, 2 = roundstart 3 = roundstop
		union zoneparts part;
};

struct zone {
		char* domain;
		struct zoneentry** entries;
		size_t entry_count;
};

int domeq(const char* dom1, const char* dom2, int ext);

int addZoneEntry(struct zone* zone, struct zoneentry* entry);

int readZone(struct zone* zone, char* file, char* relpath, struct logsess* log);

#endif /* ZONE_H_ */
