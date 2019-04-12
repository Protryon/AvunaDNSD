/*
 * zone.c
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#include "zone.h"
#include "dns.h"
#include <avuna/util.h>
#include <avuna/streams.h>
#include <avuna/string.h>
#include <avuna/pmem.h>
#include <avuna/log.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdio.h>
#include <unistd.h>

int domeq(char* domain1, char* domain2, int extensible) {
	int psuedo_matching = str_prefixes(domain1, "~");
	if (psuedo_matching && str_eq_case(domain1, "~@")) return extensible;
	if (psuedo_matching && !extensible) return 0;
	struct mempool* pool = mempool_new();
	domain1 = str_dup(domain1, 1, pool);
	size_t domain1_length = strlen(domain1);
	for (size_t i = 0; i < domain1_length; i++) {
		if (domain1[i] == '.') domain1[i] = 0;
	}
	domain1[domain1_length + 1] = 0;
	domain2 = str_dup(domain2, 0, pool);
	char* strtok_context = NULL;
	char* current_token = NULL;
	while (strlen(domain1) > 0) {
		current_token = strtok_r(current_token == NULL ? domain2 : NULL, ".", &strtok_context);
		if (str_eq_case(domain1, "*") || str_eq_case(domain1, "@")) goto cont;
		if (str_eq_case(domain1, "**")) {
			char* new_domain1 = domain1 + strlen(domain1) + 1;
			size_t new_domain1_length = strlen(new_domain1);
			if (current_token == NULL && new_domain1_length == 0) break;
			else if (current_token == NULL) {
				pfree(pool);
				return 0;
			}
			if (new_domain1_length > 0 && (!(str_eq_case(new_domain1, "*") || str_eq_case(new_domain1, "@")) && !str_eq(new_domain1, current_token))) {
				continue;
			} else {
				domain1 = new_domain1;
				goto cont;
			}
		}
		if (current_token == NULL || !str_eq(domain1, current_token)) {
			pfree(pool);
			return 0;
		}
		cont: ;
		domain1 = domain1 + strlen(domain1) + 1;
	}
	pfree(pool);
	return psuedo_matching ? extensible : 1;
}

int zone_add_entry(struct zone* zone, struct zone_entry* entry) {
	list_append(zone->entries, entry);
	return 0;
}

const char* typeString(int type) {
	if (type == DNS_A) return "A";
	else if (type == DNS_NS) return "NS";
	else if (type == DNS_CNAME) return "CNAME";
	else if (type == DNS_SOA) return "SOA";
	else if (type == DNS_PTR) return "PTR";
	else if (type == DNS_MX) return "MX";
	else if (type == DNS_TXT) return "TXT";
	else if (type == DNS_RP) return "RP";
	else if (type == DNS_AAAA) return "AAAA";
	else if (type == DNS_SRV) return "SRV";
	else if (type == DNS_CERT) return "CERT";
	else if (type == DNS_DNAME) return "DNAME";
	else if (type == DNS_SSHFP) return "SSHFP";
	else if (type == DNS_IPSECKEY) return "IPSECKEY";
	else if (type == DNS_DHCID) return "DHCID";
	else if (type == DNS_TLSA) return "TLSA";
	else if (type == DNS_STAR) return "*";
	else if (type == DNS_CAA) return "CAA";
	static char p[32];
	snprintf(p, 32, "%i", type);
	return p;
}


int typeInt(const char* type) {
	if (str_eq(type, "a")) return DNS_A;
	else if (str_eq(type, "ns")) return DNS_NS;
	else if (str_eq(type, "cname")) return DNS_CNAME;
	else if (str_eq(type, "soa")) return DNS_SOA;
	else if (str_eq(type, "ptr")) return DNS_PTR;
	else if (str_eq(type, "mx")) return DNS_MX;
	else if (str_eq(type, "txt")) return DNS_TXT;
	else if (str_eq(type, "rp")) return DNS_RP;
	else if (str_eq(type, "aaaa")) return DNS_AAAA;
	else if (str_eq(type, "srv")) return DNS_SRV;
	else if (str_eq(type, "cert")) return DNS_CERT;
	else if (str_eq(type, "dname")) return DNS_DNAME;
	else if (str_eq(type, "sshfp")) return DNS_SSHFP;
	else if (str_eq(type, "ipseckey")) return DNS_IPSECKEY;
	else if (str_eq(type, "dhcid")) return DNS_DHCID;
	else if (str_eq(type, "tlsa")) return DNS_TLSA;
	else if (str_eq(type, "*")) return DNS_STAR;
	else if (str_eq(type, "caa")) return DNS_CAA;
	return -1;
}

void zone_parse_dns_entry(struct mempool* pool, struct logsess* log, char* file, ssize_t line_number, struct dns_entry* dns_entry, char* args[], size_t arg_count) {
	struct dns_record* record = dns_entry->record = pcalloc(pool, sizeof(struct dns_record));
	record->domain = str_dup(args[0], 0, pool);
	char* ttl_split = strchr(args[2], '-');
	if (ttl_split == NULL) {
		uint32_t k = (uint32_t) strtoul(args[2], NULL, 10);
		dns_entry->ttl_minimum = k;
		dns_entry->ttl_maximum = k;
	} else {
		ttl_split[0] = 0;
		ttl_split++;
		dns_entry->ttl_minimum = (uint32_t) strtoul(args[2], NULL, 10);
		dns_entry->ttl_maximum = (uint32_t) strtoul(ttl_split, NULL, 10);
		ttl_split[-1] = '-';
	}
	int data_type = 0; // 0 for none, 1 for ip4, 2 for ip6, 3 for domain, 4 for text
	int data_argument_index = 3;
	dns_entry->is_psuedo_type = 0;
	char* description = NULL;
	size_t description_index = 0;
	for (int i = 3; i < arg_count; i++) {
		size_t argument_length = strlen(args[i]);
		description = prealloc(pool, description, description_index + argument_length + 2);
		memcpy(description + description_index, args[i], argument_length);
		description_index += argument_length;
		description[description_index++] = ' ';
		description[description_index] = 0;
	}
	if (description != NULL) description[description_index - 1] = 0;
	else description = "";
	record->description = description;
	int type = typeInt(args[1]);
	if (type < 0) {
		errlog(log, "line %s:%u: invalid domain record, invalid type.", file, line_number);
		return;
	}
	record->type = (uint16_t) type;
	if (arg_count == 3) {
		dns_entry->is_negative = 1;
		return;
	}
	if (record->type == DNS_A) {
		data_type = 1;
	} else if (record->type == DNS_NS || record->type == DNS_CNAME || record->type == DNS_PTR || record->type == DNS_DNAME) {
		data_type = 3;
	} else if (record->type == DNS_SOA) {
		if (arg_count != 10) {
			errlog(log, "line %s:%u: invalid SOA record, expected 10 arguments.", file, line_number);
			return;
		}
		record->data.soa.mname = str_dup(args[3], 0, pool);
		record->data.soa.rname = str_dup(args[4], 0, pool);
		record->data.soa.serial = (uint32_t) strtoul(args[5], NULL, 10);
		record->data.soa.refresh = (uint32_t) strtoul(args[6], NULL, 10);
		record->data.soa.retry = (uint32_t) strtoul(args[7], NULL, 10);
		record->data.soa.expire = (uint32_t) strtoul(args[8], NULL, 10);
		record->data.soa.minimum = (uint32_t) strtoul(args[9], NULL, 10);
	} else if (record->type == DNS_MX) {
		if (arg_count != 5) {
			errlog(log, "line %s:%u: invalid MX record, expected 5 arguments.", file, line_number);
			return;
		}
		uint16_t pref = (uint16_t) strtoul(args[3], NULL, 10);
		record->data.appended_domain.data = pmalloc(pool, sizeof(uint16_t));
		memcpy(record->data.appended_domain.data, &pref, sizeof(uint16_t));
		record->rdlength = sizeof(uint16_t);
		data_type = 3;
		data_argument_index = 4;
	} else if (record->type == DNS_TXT || record->type == DNS_RP) {
		data_type = 4;
	} else if (record->type == DNS_AAAA) {
		data_type = 2;
	} else if (record->type == DNS_SRV) {
		uint16_t ag[3];
		ag[0] = (uint16_t) strtoul(args[3], NULL, 10);
		ag[1] = (uint16_t) strtoul(args[4], NULL, 10);
		ag[2] = (uint16_t) strtoul(args[5], NULL, 10);
		record->data.appended_domain.data = xcopy(ag, 6, 0, pool);
		record->rdlength = 6;
		data_type = 3;
		data_argument_index = 6;
	}

	if (data_type == 1) {
		struct in_addr ia;
		if (inet_aton(args[data_argument_index], &ia) != 0) {
			record->data.data = prealloc(pool, record->data.data, record->rdlength + sizeof(in_addr_t));
			memcpy(record->data.data + record->rdlength, &ia.s_addr, sizeof(in_addr_t));
			record->rdlength += sizeof(in_addr_t);
		} else {
			errlog(log, "line %s:%u: invalid %s record, invalid IP.", file, line_number, args[1]);
			return;
		}
	} else if (data_type == 2) {
		struct in6_addr ia;
		if (inet_pton(AF_INET6, args[data_argument_index], &ia) != 0) {
			record->data.data = prealloc(pool, record->data.data, record->rdlength + sizeof(struct in6_addr));
			memcpy(record->data.data + record->rdlength, &ia, sizeof(struct in6_addr));
			record->rdlength += sizeof(struct in6_addr);
		} else {
			errlog(log, "line %s:%u: invalid %s record, invalid IP.", file, line_number, args[1]);
			return;
		}
	} else if (data_type == 3) {
		record->data.appended_domain.domain = str_dup(args[data_argument_index], 0, pool);
	} else if (data_type == 4) {
		size_t arg_length = strlen(args[data_argument_index]);
		if (arg_length > 255) arg_length = 255;
		record->data.data = prealloc(pool, record->data.data, record->rdlength + arg_length + 1);
		record->data.data[record->rdlength++] = (uint8_t) arg_length;
		memcpy(record->data.data + record->rdlength, args[data_argument_index], arg_length);
		record->rdlength += arg_length;
	}
}

int zone_read(struct zone* zone, char* file, char* relative_path, struct logsess* log) {
	zone->entries = list_new(16, zone->pool);
	int fd = open(file, O_RDONLY);
	if (fd < 0) return -1;
	char line[1024];
	size_t line_number = 0;
	while (readLine(fd, line, 1024) >= 0) {
		line_number++;
		char* comment_start = NULL;
		if ((comment_start = strchr(line, '#')) != NULL) {
			comment_start[0] = 0;
			comment_start++;
		}
		char* line_trim = str_trim(line);
		size_t line_trim_length = strlen(line_trim);
		if (line_trim_length <= 0) continue;
		int in_quote = 0, in_escape = 0;
		char* args[512];
		int arg_count = 0;
		args[arg_count++] = line_trim + (line_trim[0] == '"' ? 1 : 0);
		for (size_t i = 0; i < line_trim_length; i++) {
			if (line_trim[i] == '\\') { // TODO: remove extra backslashes
				in_escape = !in_escape;
			}
			if (!in_escape && line_trim[i] == '"') {
				in_quote = !in_quote;
			} else if (!in_escape && !in_quote && isspace(line_trim[i])) {
				line_trim[i] = 0;
				if (i > 0 && line_trim[i - 1] == '"') line_trim[i - 1] = 0;
				args[arg_count++] = line_trim + i + 1;
			}
			if (arg_count > 510) break;
		}
		args[arg_count] = NULL;
		if (str_eq(args[0], "$zone")) {
			if (arg_count != 3) {
				errlog(log, "line %s:%u: invalid zone directive, expected 2 arguments.", file, line_number);
				continue;
			}
			struct mempool* pool = mempool_new();
			pchild(zone->pool, pool);
			struct zone* sub_zone = pmalloc(pool, sizeof(struct zone));
			sub_zone->domain = str_dup(args[1], 0, pool);
			sub_zone->pool = pool;
			char* sub_zone_file = NULL;
			if (args[2][0] == '/') {
				sub_zone_file = args[2];
			} else {
				size_t relative_path_length = strlen(relative_path);
				size_t arg_length = strlen(args[2]);
				sub_zone_file = pmalloc(pool, relative_path_length + arg_length + 2);
				memcpy(sub_zone_file, relative_path, relative_path_length);
				int ended_non_slash = 0;
				if (relative_path[relative_path_length - 1] != '/') {
					sub_zone_file[relative_path_length] = '/';
					ended_non_slash = 1;
				}
				memcpy(sub_zone_file + relative_path_length + (ended_non_slash ? 1 : 0), args[2], arg_length);
				sub_zone_file[relative_path_length + (ended_non_slash ? 1 : 0) + arg_length] = 0;
			}
			if (zone_read(sub_zone, sub_zone_file, relative_path, log) == -1) {
				errlog(log, "line %s:%u: error reading subzone %s.", file, line_number, sub_zone_file);
				pfree(sub_zone->pool);
				continue;
			}
			struct zone_entry* entry = pcalloc(zone->pool, sizeof(struct zone_entry));
			entry->type = ZONE_SUBZONE;
			entry->part.subzone = sub_zone;
			zone_add_entry(zone, entry);
		} else if (str_eq(args[0], "$roundstart")) {
			struct zone_entry* entry = pcalloc(zone->pool, sizeof(struct zone_entry));
			entry->type = ZONE_ROUNDSTART;
			entry->part.roundrobin.per = strtoul(args[1], NULL, 10);
			zone_add_entry(zone, entry);
		} else if (str_eq(args[0], "$roundstop")) {
			struct zone_entry* entry = pcalloc(zone->pool, sizeof(struct zone_entry));
			entry->type = ZONE_ROUNDSTOP;
			zone_add_entry(zone, entry);
		} else {
			if (arg_count < 3) {
				errlog(log, "line %s:%u: invalid domain record, expected at least 3 arguments.", file, line_number);
				continue;
			}
			struct zone_entry* entry = pcalloc(zone->pool, sizeof(struct zone_entry));
			entry->type = ZONE_ENTRY;
			struct dns_entry* dns_entry = &entry->part.dom;
			zone_parse_dns_entry(zone->pool, log, file, line_number, dns_entry, args, arg_count);
			zone_add_entry(zone, entry);
		}
	}
	close(fd);
	return 0;
}

