/*
 * zone.c
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#include "zone.h"
#include "util.h"
#include <fcntl.h>
#include "streams.h"
#include "xstring.h"
#include <errno.h>
#include "log.h"

int domeq(const char* dom1, const char* dom2) { // TODO: ~@
	if (streq_nocase(dom1, dom2)) return 1;
	if (streq(dom1, "@")) return 1;
	return 0;
}

int addZoneEntry(struct zone* zone, struct zoneentry* entry) {
	if (zone->entries == NULL) {
		zone->entries = xmalloc(sizeof(struct zoneentry*));
		zone->entry_count = 0;
	} else {
		zone->entries = xrealloc(zone->entries, sizeof(struct zoneentry*) * (zone->entry_count + 1));
	}
	zone->entries[zone->entry_count] = xmalloc(sizeof(struct zoneentry));
	memcpy(zone->entries[zone->entry_count], entry, sizeof(struct zoneentry));
	zone->entry_count++;
	return 0;
}

int readZone(struct zone* zone, char* file, char* relpath, struct logsess* log) {
	zone->entry_count = 0;
	zone->entries = NULL;
	int fd = open(file, O_RDONLY);
	if (fd < 0) return -1;
	char line[1024];
	ssize_t ret;
	size_t li = 0;
	while ((ret = readLine(fd, line, 1024)) >= 0) {
		li++;
		char* cl = NULL;
		if ((cl = strchr(line, '#')) != NULL) {
			cl[0] = 0;
			cl++;
		}
		char* rl = trim(line);
		size_t ll = strlen(rl);
		if (ll <= 0) continue;
		int iq = 0, ie = 0;
		char* args[512];
		int ai = 0;
		args[ai++] = rl + (rl[0] == '"' ? 1 : 0);
		for (size_t i = 0; i < ll; i++) {
			if (rl[i] == '\\') { // TODO: remove extra backslashes
				ie = !ie;
			}
			if (!ie && rl[i] == '"') {
				iq = !iq;
			} else if (!ie && !iq && isspace(rl[i])) {
				rl[i] = 0;
				if (i > 0 && rl[i - 1] == '"') rl[i - 1] = 0;
				args[ai++] = rl + i + 1;
			}
		}
		args[ai] = NULL;
		if (streq_nocase(args[0], "$zone")) {
			if (ai != 3) {
				errlog(log, "line %s:%u: invalid zone directive, expected 2 arguments.", file, li);
				continue;
			}
			struct zone* szone = xmalloc(sizeof(struct zone));
			szone->domain = xstrdup(args[1], 0);
			char* rf = NULL;
			if (args[2][0] == '/') {
				rf = args[2];
			} else {
				size_t rpl = strlen(relpath);
				size_t apl = strlen(args[2]);
				rf = xmalloc(rpl + apl + 2);
				memcpy(rf, relpath, rpl);
				int k = 0;
				if (relpath[rpl - 1] != '/') {
					rf[rpl] = '/';
					k = 1;
				}
				memcpy(rf + rpl + (k ? 1 : 0), args[2], apl);
				rf[rpl + (k ? 1 : 0) + apl] = 0;
			}
			if (readZone(szone, rf, relpath, log) == -1) {
				xfree(szone);
				errlog(log, "line %s:%u: error reading subzone %s.", file, li, rf);
				if (rf != args[2]) xfree(rf);
				continue;
			}
			if (rf != args[2]) xfree(rf);
			struct zoneentry entry;
			entry.type = 0;
			entry.part.subzone = szone;
			addZoneEntry(zone, &entry);
		} else if (streq_nocase(args[0], "$roundstart")) {
			struct zoneentry entry;
			entry.type = 2;
			entry.part.rrst.per = atoi(args[2]);
			addZoneEntry(zone, &entry);
		} else if (streq_nocase(args[0], "$roundstop")) {
			struct zoneentry entry;
			entry.type = 3;
			addZoneEntry(zone, &entry);
		} else {
			if (ai < 4) {
				errlog(log, "line %s:%u: invalid domain record, expected at least 4 arguments.", file, li);
				continue;
			}
			struct zoneentry entry;
			entry.type = 1;
			struct domentry* de = &entry.part.dom;
			de->domain = strdup(args[0]);
			de->data_len = 0;
			de->data = NULL;
			de->ttl = atoi(args[2]);
			int dt = 0; // 0 for none, 1 for ip4, 2 for ip6, 3 for domain, 4 for text
			int da = 3;
			if (streq_nocase(args[1], "a")) {
				de->type = 1;
				dt = 1;
			} else if (streq_nocase(args[1], "ns")) {
				de->type = 2;
				dt = 3;
			} else if (streq_nocase(args[1], "cname")) {
				de->type = 5;
				dt = 3;
			} else if (streq_nocase(args[1], "soa")) {
				de->type = 6;
			} else if (streq_nocase(args[1], "ptr")) {
				de->type = 12;
				dt = 3;
			} else if (streq_nocase(args[1], "mx")) {
				if (ai != 5) {
					errlog(log, "line %s:%u: invalid MX record, expected 5 arguments.", file, li);
					continue;
				}
				de->type = 15;
				uint16_t pref = atoi(args[4]);
				de->data = xmalloc(sizeof(uint16_t));
				memcpy(de->data, &pref, sizeof(uint16_t));
				de->data_len = sizeof(uint16_t);
				dt = 3;
				da = 4;
			} else if (streq_nocase(args[1], "txt")) {
				de->type = 16;
				dt = 4;
			} else if (streq_nocase(args[1], "rp")) {
				de->type = 17;
				dt = 4; //?
			} else if (streq_nocase(args[1], "aaaa")) {
				de->type = 28;
				dt = 2;
			} else if (streq_nocase(args[1], "srv")) {
				de->type = 33;
				de->data_len = 6;
				uint16_t ag[3];
				ag[0] = atoi(args[3]);
				ag[1] = atoi(args[4]);
				ag[2] = atoi(args[5]);
				memcpy(de->data, ag, sizeof(uint16_t) * 3);
				dt = 3;
				da = 6;
			} else if (streq_nocase(args[1], "cert")) {
				de->type = 37;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else if (streq_nocase(args[1], "dname")) {
				de->type = 39;
				dt = 3;
			} else if (streq_nocase(args[1], "sshfp")) {
				de->type = 44;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else if (streq_nocase(args[1], "ipseckey")) {
				de->type = 45;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else if (streq_nocase(args[1], "dhcid")) {
				de->type = 49;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else if (streq_nocase(args[1], "tlsa")) {
				de->type = 52;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else if (streq_nocase(args[1], "caa")) {
				de->type = 257;
				errlog(log, "line %s:%u: invalid %s record, not yet implemented.", file, li, args[1]);
				continue;
			} else {
				errlog(log, "line %s:%u: invalid domain record, invalid type.", file, li);
				continue;
			}
			if (dt == 1) {
				struct in_addr ia;
				if (inet_aton(args[da], &ia) != 0) {
					if (de->data == NULL) {
						de->data = xmalloc(sizeof(in_addr_t));
					} else {
						de->data = xrealloc(de->data, de->data_len + sizeof(in_addr_t));
					}
					memcpy(de->data + de->data_len, &ia.s_addr, sizeof(in_addr_t));
					de->data_len += sizeof(in_addr_t);
				} else {
					errlog(log, "line %s:%u: invalid %s record, invalid IP.", file, li, args[1]);
					continue;
				}
			} else if (dt == 2) {
				struct in6_addr ia;
				if (inet_pton(AF_INET6, args[da], &ia) != 0) {
					if (de->data == NULL) {
						de->data = xmalloc(sizeof(struct in6_addr));
					} else {
						de->data = xrealloc(de->data, de->data_len + sizeof(struct in6_addr));
					}
					memcpy(de->data + de->data_len, &ia, sizeof(struct in6_addr));
					de->data_len += sizeof(struct in6_addr);
				} else {
					errlog(log, "line %s:%u: invalid %s record, invalid IP.", file, li, args[1]);
					continue;
				}
			} else if (dt == 3) {
				size_t sl = strlen(args[da]);
				int ed = sl > 0 && args[da][sl - 1] == '.';
				size_t fl = sl + 1 + (!ed ? 1 : 0);
				char* dd = xmalloc(fl);
				for (int i = 0; i < sl; i++) {
					if (args[da][i] == '.') dd[i] = 0;
					else dd[i] = args[da][i];
				}
				if (!ed) {
					dd[fl - 2] = '.';
					dd[fl - 1] = 0;
				}
				if (de->data == NULL) {
					de->data = xmalloc(fl);
				} else {
					de->data = xrealloc(de->data, de->data_len + fl - 1);
				}
				memcpy(de->data + de->data_len, dd, fl - 1);
				de->data_len += fl - 1;
			} else if (dt == 4) {
				size_t sl = strlen(args[da]);
				if (de->data == NULL) {
					de->data = xmalloc(sl);
				} else {
					de->data = xrealloc(de->data, de->data_len + sl);
				}
				memcpy(de->data + de->data_len, args[da], sl);
				de->data_len += sl;
			}
			addZoneEntry(zone, &entry);
		}
	}
	if (ret < 0) return -1;
	return 0;
}

