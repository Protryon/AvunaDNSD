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
#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "udpwork.h"
#include <stdio.h>
#include <unistd.h>

int domeq(const char* dom1, const char* dom2, int ext) {
	int psu = startsWith(dom1, "~");
	if (psu && streq(dom1, "~@")) return ext;
	if (psu && !ext) return 0;
	char* d1 = xstrdup(dom1, 1);
	size_t d1l = strlen(dom1);
	for (size_t i = 0; i < d1l; i++) {
		if (d1[i] == '.') d1[i] = 0;
	}
	d1[d1l + 1] = 0;
	char* od1 = d1;
	char* d2 = xstrdup(dom2, 0);
	char* sp2 = NULL;
	char* m2 = NULL;
	while (strlen(d1) > 0) {
		m2 = strtok_r(m2 == NULL ? d2 : NULL, ".", &sp2);
		if (streq(d1, "*") || streq(d1, "@")) goto cont;
		if (streq(d1, "**")) {
			char* nd = d1 + strlen(d1) + 1;
			if (m2 == NULL && strlen(nd) == 0) break;
			else if (m2 == NULL) {
				xfree(od1);
				xfree(d2);
				return 0;
			}
			if (strlen(nd) > 0 && (!(streq(nd, "*") || streq(nd, "@")) && !streq_nocase(nd, m2))) {
				continue;
			} else {
				d1 = nd;
				goto cont;
			}
		}
		if (m2 == NULL || !streq_nocase(d1, m2)) {
			xfree(od1);
			xfree(d2);
			return 0;
		}
		cont: ;
		d1 = d1 + strlen(d1) + 1;
	}
	xfree(od1);
	xfree(d2);
	return psu ? ext : 1;
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

const char* typeString(int type) {
	if (type == 1) return "A";
	else if (type == 2) return "NS";
	else if (type == 5) return "CNAME";
	else if (type == 6) return "SOA";
	else if (type == 12) return "PTR";
	else if (type == 15) return "MX";
	else if (type == 16) return "TXT";
	else if (type == 17) return "RP";
	else if (type == 28) return "AAAA";
	else if (type == 33) return "SRV";
	else if (type == 37) return "CERT";
	else if (type == 39) return "DNAME";
	else if (type == 44) return "SSHFP";
	else if (type == 45) return "IPSECKEY";
	else if (type == 49) return "DHCID";
	else if (type == 52) return "TLSA";
	else if (type == 255) return "*";
	else if (type == 257) return "CAA";
	static char p[32];
	snprintf(p, 32, "%i", type);
	return p;
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
			if (ai > 510) break;
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
			entry.part.rrst.per = atoi(args[1]);
			addZoneEntry(zone, &entry);
		} else if (streq_nocase(args[0], "$roundstop")) {
			struct zoneentry entry;
			entry.type = 3;
			addZoneEntry(zone, &entry);
		} else {
			if (ai < 3) {
				errlog(log, "line %s:%u: invalid domain record, expected at least 3 arguments.", file, li);
				continue;
			}
			struct zoneentry entry;
			entry.type = 1;
			struct domentry* de = &entry.part.dom;
			de->ad = NULL;
			de->domain = strdup(args[0]);
			de->data_len = 0;
			de->data = NULL;
			char* dj = strchr(args[2], '-');
			if (dj == NULL) {
				int k = atol(args[2]);
				de->ttlmin = k;
				de->ttlmax = k;
			} else {
				dj[0] = 0;
				dj++;
				de->ttlmin = atol(args[2]);
				de->ttlmax = atol(dj);
			}
			int dt = 0; // 0 for none, 1 for ip4, 2 for ip6, 3 for domain, 4 for text
			int da = 3;
			de->pt = 0;
			char* desc = NULL;
			size_t sltb = 0;
			if (ai > 3) for (int i = 3; i < ai; i++) {
				size_t slt = strlen(args[i]);
				if (desc == NULL) {
					desc = xmalloc(slt + 2);
				} else {
					desc = xrealloc(desc, sltb + slt + 2);
				}
				memcpy(desc + sltb, args[i], slt);
				sltb += slt;
				desc[sltb++] = ' ';
				desc[sltb] = 0;
			}
			if (desc != NULL) desc[sltb - 1] = 0;
			else desc = "";
			de->pdata = desc;
			//if (startsWith(args[1], "~")) {
			//	de->pt = 1;
			//	args[1]++;
			//}
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
				if (ai == 3) {
					de->data_len = 0;
					de->data = NULL;
					goto eg;
				}
				if (ai != 10) {
					errlog(log, "line %s:%u: invalid SOA record, expected 10 arguments.", file, li);
					continue;
				}
				de->type = 6;
				de->pd1 = xstrdup(args[3], 0);
				de->pd2 = xstrdup(args[4], 0);
				de->data_len = 20;
				de->data = xmalloc(20);
				uint32_t t = htonl(atol(args[5]));
				memcpy(de->data, &t, 4);
				t = htonl(atoi(args[6]));
				memcpy(de->data + 4, &t, 4);
				t = htonl(atoi(args[7]));
				memcpy(de->data + 8, &t, 4);
				t = htonl(atoi(args[8]));
				memcpy(de->data + 12, &t, 4);
				t = htonl(atoi(args[9]));
				memcpy(de->data + 16, &t, 4);
			} else if (streq_nocase(args[1], "ptr")) {
				de->type = 12;
				dt = 3;
			} else if (streq_nocase(args[1], "mx")) {
				if (ai == 3) {
					de->data_len = 0;
					de->data = NULL;
					goto eg;
				}
				if (ai != 5) {
					errlog(log, "line %s:%u: invalid MX record, expected 5 arguments.", file, li);
					continue;
				}
				de->type = 15;
				uint16_t pref = atoi(args[3]);
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
				if (ai == 3) {
					de->data_len = 0;
					de->data = NULL;
					goto eg;
				}
				de->type = 33;
				de->data_len = 6;
				uint16_t ag[3];
				ag[0] = htons(atoi(args[3]));
				ag[1] = htons(atoi(args[4]));
				ag[2] = htons(atoi(args[5]));
				de->data = xmalloc(sizeof(uint16_t) * 3);
				memcpy(de->data, ag, sizeof(uint16_t) * 3);
				dt = 3;
				da = 6;
			} else if (streq_nocase(args[1], "dname")) {
				de->type = 39;
				dt = 3;
			} else {
				errlog(log, "line %s:%u: invalid domain record, invalid type.", file, li);
				continue;
			}
			eg: ;
			if (ai == 3) {
				de->data_len = 0;
				de->data = NULL;
				goto az;
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
				de->ad = xstrdup(args[da], 0);
				//writeDomain(0, args[da], de->data, sl + de->data_len, &de->data_len);
				//de->data_len += sl;
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
			az: ;
			addZoneEntry(zone, &entry);
		}
	}
	close(fd);
	return 0;
}

void freeZone(struct zone* zone) {
	if (zone->domain != NULL) xfree(zone->domain);
	for (size_t i = 0; i < zone->entry_count; i++) {
		struct zoneentry* ze = zone->entries[i];
		if (ze->type == 0) freeZone(ze->part.subzone);
		else if (ze->type == 1) {
			if (ze->part.dom.domain != NULL) xfree(ze->part.dom.domain);
			if (ze->part.dom.ad != NULL) xfree(ze->part.dom.ad);
			if (ze->part.dom.data != NULL) xfree(ze->part.dom.data);
			if (ze->part.dom.pd1 != NULL) xfree(ze->part.dom.pd1);
			if (ze->part.dom.pd2 != NULL) xfree(ze->part.dom.pd2);
			if (ze->part.dom.pdata != NULL) xfree(ze->part.dom.pdata);
		}
	}
}

