/*
 * mysql_parser.c
 *
 *  Created on: Jun 19, 2016
 *      Author: root
 */
#include "globals.h"
#ifdef SUPPORTS_MYSQL

#include "mysql_parser.h"
#include "udpwork.h"
#include <mysql/mysql.h>
#include "util.h"
#include "xstring.h"
#include <ctype.h>
#include "zone.h"
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int mysql_recurse(MYSQL_RES* wres, struct zone* czone, int zid) {
	mysql_data_seek(wres, 0);
	MYSQL_ROW row;
	int ru = 1;
	long int lrrc = 0;
	while ((row = mysql_fetch_row(wres)) != NULL) {
		if (strtol(row[3], NULL, 10) != zid) {
			ru++;
			continue;
		}
		if (czone->entries == NULL) {
			czone->entries = xmalloc(sizeof(struct zoneentry*));
			czone->entry_count = 0;
		} else czone->entries = xrealloc(czone->entries, sizeof(struct zoneentry*) * (czone->entry_count + 1));
		struct zoneentry* ze = xmalloc(sizeof(struct zoneentry));
		czone->entries[czone->entry_count++] = ze;
		long int rrc = strtol(row[4], NULL, 10);
		int skc = 0;
		if (rrc != lrrc && lrrc == 0) {
			ze->type = 2;
			ze->part.rrst.per = rrc;
			skc = 1;
		} else if (rrc != lrrc && rrc == 0) {
			ze->type = 3;
			skc = 1;
		} else if (rrc != lrrc) {
			ze->type = 3;
			skc = 1;
			czone->entries = xrealloc(czone->entries, sizeof(struct zoneentry*) * (czone->entry_count + 1));
			ze = xmalloc(sizeof(struct zoneentry));
			czone->entries[czone->entry_count++] = ze;
			ze->type = 2;
			ze->part.rrst.per = rrc;
		}
		if (skc) {
			czone->entries = xrealloc(czone->entries, sizeof(struct zoneentry*) * (czone->entry_count + 1));
			ze = xmalloc(sizeof(struct zoneentry));
			czone->entries[czone->entry_count++] = ze;
		}
		if (row[5] == NULL) {
			ze->type = 0;
			ze->part.subzone = xmalloc(sizeof(struct zone));
			ze->part.subzone->domain = xstrdup(row[1], 0);
			ze->part.subzone->entries = NULL;
			ze->part.subzone->entry_count = 0;
			int szid = strtol(row[0], NULL, 10);
			if (mysql_recurse(wres, ze->part.subzone, szid) == -1) return -1;
			mysql_data_seek(wres, ru);
		} else {
			char* ogd = xstrdup(row[7], 0);
			char* args[64];
			int ai = 0;
			int ie = 0;
			int iq = 0;
			size_t ogdl = strlen(ogd);
			args[ai++] = ogd + ((ogdl > 0 && ogd[0] == '"') ? 1 : 0);
			for (size_t i = 0; i < ogdl; i++) {
				if (ogd[i] == '\\') { // TODO: remove extra backslashes
					ie = !ie;
				}
				if (!ie && ogd[i] == '"') {
					iq = !iq;
				} else if (!ie && !iq && isspace(ogd[i])) {
					ogd[i] = 0;
					if (i > 0 && ogd[i - 1] == '"') ogd[i - 1] = 0;
					args[ai++] = ogd + i + 1;
				}
				if (ai > 62) break;
			}
			if (ai > 0) {
				size_t slxx = strlen(args[ai - 1]);
				if(slxx > 0 && args[ai - 1][slxx - 1] == '"') args[ai - 1][slxx - 1] = 0;
			}
			args[ai] = NULL;
			ze->type = 1;
			struct domentry* de = &ze->part.dom;
			de->ad = NULL;
			de->domain = xstrdup(row[1], 0);
			de->data_len = 0;
			de->data = NULL;
			de->pd1 = NULL;
			de->pd2 = NULL;
			de->pdata = NULL;
			de->pt = 0;
			char* tdj = xstrdup(row[6], 0);
			char* dj = strchr(tdj, '-');
			if (dj == NULL) {
				int k = atol(tdj);
				de->ttlmin = k;
				de->ttlmax = k;
			} else {
				dj[0] = 0;
				dj++;
				de->ttlmin = atol(tdj);
				de->ttlmax = atol(dj);
			}
			xfree(tdj);
			int dt = 0; // 0 for none, 1 for ip4, 2 for ip6, 3 for domain, 4 for text
			int da = 0;
			size_t sltb = 0;
			de->pdata = xstrdup(row[7], 0);
			char* tt = row[5];
			if (startsWith(tt, "~")) {
				de->pt = 1;
				tt++;
			}
			if (streq_nocase(tt, "a")) {
				de->type = 1;
				dt = 1;
			} else if (streq_nocase(tt, "ns")) {
				de->type = 2;
				dt = 3;
			} else if (streq_nocase(tt, "cname")) {
				de->type = 5;
				dt = 3;
			} else if (streq_nocase(tt, "soa")) {
				if (ai != 7) {
					de->data_len = 0;
					de->data = NULL;
					goto eg2;
				}
				de->type = 6;
				de->pd1 = xstrdup(args[0], 0);
				de->pd2 = xstrdup(args[1], 0);
				de->data_len = 20;
				de->data = xmalloc(20);
				uint32_t t = htonl(atol(args[2]));
				memcpy(de->data, &t, 4);
				t = htonl(atoi(args[3]));
				memcpy(de->data + 4, &t, 4);
				t = htonl(atoi(args[4]));
				memcpy(de->data + 8, &t, 4);
				t = htonl(atoi(args[5]));
				memcpy(de->data + 12, &t, 4);
				t = htonl(atoi(args[6]));
				memcpy(de->data + 16, &t, 4);
			} else if (streq_nocase(tt, "ptr")) {
				de->type = 12;
				dt = 3;
			} else if (streq_nocase(tt, "mx")) {
				if (ai != 2) {
					de->data_len = 0;
					de->data = NULL;
					goto eg2;
				}
				de->type = 15;
				uint16_t pref = atoi(args[0]);
				de->data = xmalloc(sizeof(uint16_t));
				memcpy(de->data, &pref, sizeof(uint16_t));
				de->data_len = sizeof(uint16_t);
				dt = 3;
				da = 1;
			} else if (streq_nocase(tt, "txt")) {
				de->type = 16;
				dt = 4;
			} else if (streq_nocase(tt, "rp")) {
				de->type = 17;
				dt = 4; //?
			} else if (streq_nocase(tt, "aaaa")) {
				de->type = 28;
				dt = 2;
			} else if (streq_nocase(tt, "srv")) {
				if (ai != 4) {
					de->data_len = 0;
					de->data = NULL;
					goto eg2;
				}
				de->type = 33;
				de->data_len = 6;
				uint16_t ag[3];
				ag[0] = htons(atoi(args[0]));
				ag[1] = htons(atoi(args[1]));
				ag[2] = htons(atoi(args[2]));
				de->data = xmalloc(sizeof(uint16_t) * 3);
				memcpy(de->data, ag, sizeof(uint16_t) * 3);
				dt = 3;
				da = 3;
			} else if (streq_nocase(tt, "dname")) {
				de->type = 39;
				dt = 3;
			} else {
				continue;
			}
			eg2:;
			if (ai == 0) {
				de->data_len = 0;
				de->data = NULL;
				goto az2;
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
					continue;
				}
			} else if (dt == 3) {
				de->ad = xstrdup(args[da], 0);
				//writeDomain(0, args[da], de->data, sl + de->data_len, &de->data_len);
				//de->data_len += sl;
			} else if (dt == 4) {
				size_t sl = strlen(args[da]);
				if (sl > 255) sl = 255;
				de->data = xrealloc(de->data, de->data_len + sl + 1);
				((uint8_t*) de->data)[de->data_len++] = (uint8_t) sl;
				memcpy(de->data + de->data_len, args[da], sl);
				de->data_len += sl;
			}
			az2:;
			xfree(ogd);
		}
		ru++;
		lrrc = rrc;
	}
	if(lrrc != 0) {
		if (czone->entries == NULL) {
			czone->entries = xmalloc(sizeof(struct zoneentry*));
			czone->entry_count = 0;
		} else czone->entries = xrealloc(czone->entries, sizeof(struct zoneentry*) * (czone->entry_count + 1));
		struct zoneentry* ze = xmalloc(sizeof(struct zoneentry));
		czone->entries[czone->entry_count++] = ze;
		ze->type = 3;
	}
	return 0;
}

void mysql_thread(struct mysql_data* data) {
	char pcheck[256];
	pcheck[255] = 0;
	pcheck[0] = 0;
	while (1) {
		data->complete = 0;
		MYSQL* db_conn = mysql_init(NULL);
		if (!mysql_real_connect(db_conn, data->mysql_host, data->mysql_user, data->mysql_pass, data->mysql_schema, data->mysql_port, NULL, 0)) {
			printf("Error connecting to mysql: %s\n", mysql_error(db_conn));
			return;
		}
		if (mysql_query(db_conn, "CHECKSUM TABLE records;")) {
			printf("Error checksumming records: %s\n", mysql_error(db_conn));
			goto mcnt;
		}
		MYSQL_RES* wres = mysql_store_result(db_conn);
		if (mysql_num_rows(wres) != 1) {
			printf("Invalid checksum response number of rows: %lu\n", mysql_num_rows(wres));
			mysql_free_result(wres);
			goto mcnt;
		}
		MYSQL_ROW row = mysql_fetch_row(wres);
		if(streq_nocase(row[1], pcheck)) {
			mysql_free_result(wres);
			goto mcnt;
		}
		memcpy(pcheck, row[1], strlen(row[1]) + 1);
		mysql_free_result(wres);
		if (mysql_query(db_conn, "SELECT * FROM records WHERE domain = '@' AND rec_type IS NULL ORDER BY priority")) {
			printf("Error selecting from records: %s\n", mysql_error(db_conn));
			goto mcnt;
		}
		wres = mysql_store_result(db_conn);
		if (mysql_num_rows(wres) != 1) {
			printf("Invalid number of root zones: %lu\n", mysql_num_rows(wres));
			mysql_free_result(wres);
			goto mcnt;
		}
		row = mysql_fetch_row(wres);
		long int rid = strtol(row[0], NULL, 10);
		mysql_free_result(wres);
		if (data->czone != NULL) {
			freeZone(data->czone);
			data->czone = NULL;
		}
		data->czone = xmalloc(sizeof(struct zone));
		data->czone->domain = NULL;
		data->czone->entries = NULL;
		data->czone->entry_count = 0;
		if (mysql_query(db_conn, "SELECT * FROM records WHERE domain != '@' OR rec_type != NULL ORDER BY priority")) {
			printf("Error selecting from records: %s\n", mysql_error(db_conn));
			goto mcnt;
		}
		wres = mysql_store_result(db_conn);
		mysql_recurse(wres, data->czone, rid);
		mysql_free_result(wres);
		data->complete = 1;
		struct zone* tzone = data->szone;
		tzone = data->szone;
		data->szone = data->czone;
		data->czone = NULL;
		if (tzone != NULL) freeZone(tzone);
		mcnt:;
		mysql_close(db_conn);
		sleep(data->mysql_refresh);
	}
}

#endif
