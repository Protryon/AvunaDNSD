/*
 * mysql_parser.c
 *
 *  Created on: Jun 19, 2016
 *      Author: root
 */
#ifdef SUPPORTS_MYSQL

#include "globals.h"
#include "mysql_zone.h"
#include "zone.h"
#include <avuna/util.h>
#include <avuna/string.h>
#include <mysql/mysql.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(256) NOT NULL DEFAULT '@',
  `priority` bigint(20) NOT NULL DEFAULT '0',
  `zoneid` int(11) NOT NULL DEFAULT '0',
  `rr_count` int(11) NOT NULL DEFAULT '0',
  `rec_type` varchar(8) DEFAULT 'A',
  `rec_ttl` varchar(32) NOT NULL DEFAULT '3600',
  `rec_data` text NOT NULL,
 */

int mysql_recurse(struct mempool* pool, MYSQL_RES* mysql_result, struct zone* current_zone, uint64_t zone_id, struct mysql_zone* mysql_zone) {
	mysql_data_seek(mysql_result, 0);
	MYSQL_ROW row;
	int seek_offset = 1;
	ssize_t last_round_robin_per = 0;
	while ((row = mysql_fetch_row(mysql_result)) != NULL) {
		if (strtol(row[3], NULL, 10) != zone_id) {
			seek_offset++;
			continue;
		}
		struct zone_entry* entry = pcalloc(pool, sizeof(struct zone_entry));
		list_append(current_zone->entries, entry);
		ssize_t round_robin_per = strtol(row[4], NULL, 10);
		uint64_t row_id = strtoull(row[0], NULL, 10);
		if (round_robin_per != last_round_robin_per && last_round_robin_per == 0) {
			entry->type = ZONE_ROUNDSTART;
			entry->part.roundrobin.per = round_robin_per;
			entry = pcalloc(pool, sizeof(struct zone_entry));
		} else if (round_robin_per != last_round_robin_per && round_robin_per == 0) {
			entry->type = ZONE_ROUNDSTOP;
			entry = pcalloc(pool, sizeof(struct zone_entry));
		} else if (round_robin_per != last_round_robin_per) {
			entry->type = ZONE_ROUNDSTOP;
			entry = pcalloc(pool, sizeof(struct zone_entry));
			list_append(current_zone->entries, entry);
			entry->type = ZONE_ROUNDSTART;
			entry->part.roundrobin.per = round_robin_per;
			entry = pcalloc(pool, sizeof(struct zone_entry));
		}
		if (row[5] == NULL) { // rec_type
			entry->type = ZONE_SUBZONE;
			entry->part.subzone = pcalloc(pool, sizeof(struct zone));
			entry->part.subzone->pool = pool;
			entry->part.subzone->domain = str_dup(row[1], 0, pool);
			entry->part.subzone->entries = list_new(8, pool);
			if (mysql_recurse(pool, mysql_result, entry->part.subzone, row_id, mysql_zone) == -1) return -1;
			mysql_data_seek(mysql_result, (my_ulonglong) seek_offset);
		} else {
			char* data = str_trim(str_dup(row[7], 0, pool)); // rec_data
			char* args[64]; // status: make 3
			args[0] = row[1];
			args[1] = row[5];
			args[2] = row[6];
			size_t arg_index = 3;
			int in_escape = 0;
			int in_quote = 0;
			size_t data_length = strlen(data);
			if (data_length > 0) {
                args[arg_index++] = data + ((data_length > 0 && data[0] == '"') ? 1 : 0);
                for (size_t i = 0; i < data_length; i++) {
                    if (data[i] == '\\') { // TODO: remove extra backslashes
                        in_escape = !in_escape;
                    }
                    if (!in_escape && data[i] == '"') {
                        in_quote = !in_quote;
                    } else if (!in_escape && !in_quote && isspace(data[i])) {
                        data[i] = 0;
                        if (i > 0 && data[i - 1] == '"') data[i - 1] = 0;
                        args[arg_index++] = data + i + 1;
                    }
                    if (arg_index > 62) break;
                }
                if (arg_index > 0) {
                    size_t last_arg_length = strlen(args[arg_index - 1]);
                    if(last_arg_length > 0 && args[arg_index - 1][last_arg_length - 1] == '"') {
                        args[arg_index - 1][last_arg_length - 1] = 0;
                    }
                }
            }
            args[arg_index] = NULL;
			entry->type = ZONE_ENTRY;
			struct dns_entry* dns_entry = &entry->part.dom;
			zone_parse_dns_entry(pool, mysql_zone->zone->server->logsess, mysql_zone->schema, row_id, dns_entry, args, arg_index);
		}
		seek_offset++;
		last_round_robin_per = round_robin_per;
	}
	if(last_round_robin_per != 0) {
		struct zone_entry* entry = pcalloc(pool, sizeof(struct zone_entry));
		entry->type = ZONE_ROUNDSTOP;
		list_append(current_zone->entries, entry);
	}
	return 0;
}

void mysql_thread(struct mysql_zone* data) {
	char checksum[256];
	checksum[255] = 0;
	checksum[0] = 0;
	while (1) {
		MYSQL* db_conn = mysql_init(NULL);
		if (!mysql_real_connect(db_conn, data->host, data->username, data->password, data->schema, data->port, NULL, 0)) {
			printf("Error connecting to mysql: %s\n", mysql_error(db_conn));
			return;
		}
		if (mysql_query(db_conn, "CHECKSUM TABLE records;")) {
			printf("Error checksumming records: %s\n", mysql_error(db_conn));
			goto continue_mysql;
		}
		MYSQL_RES* mysql_result = mysql_store_result(db_conn);
		if (mysql_num_rows(mysql_result) != 1) {
			printf("Invalid checksum response number of rows: %llu\n", mysql_num_rows(mysql_result));
			mysql_free_result(mysql_result);
			goto continue_mysql;
		}
		MYSQL_ROW row = mysql_fetch_row(mysql_result);
		if(str_eq(row[1], checksum)) {
			mysql_free_result(mysql_result);
			goto continue_mysql;
		}
		memcpy(checksum, row[1], strlen(row[1]) + 1);
		mysql_free_result(mysql_result);
		if (mysql_query(db_conn, "SELECT * FROM records WHERE domain = '@' AND rec_type IS NULL ORDER BY priority")) {
			printf("Error selecting from records: %s\n", mysql_error(db_conn));
			goto continue_mysql;
		}
		mysql_result = mysql_store_result(db_conn);
		if (mysql_num_rows(mysql_result) != 1) {
			printf("Invalid number of root zones: %llu\n", mysql_num_rows(mysql_result));
			mysql_free_result(mysql_result);
			goto continue_mysql;
		}
		row = mysql_fetch_row(mysql_result);
		uint64_t row_id = strtoul(row[0], NULL, 10);
		mysql_free_result(mysql_result);
		struct mempool* pool = mempool_new();
		struct zone* completed_zone = pmalloc(pool, sizeof(struct zone));
		completed_zone->pool = pool;
		completed_zone->domain = NULL;
		completed_zone->entries = list_new(8, pool);
		if (mysql_query(db_conn, "SELECT * FROM records WHERE domain != '@' OR rec_type != NULL ORDER BY priority")) {
			printf("Error selecting from records: %s\n", mysql_error(db_conn));
			pfree(pool);
			goto continue_mysql;
		}
		mysql_result = mysql_store_result(db_conn);
		mysql_recurse(pool, mysql_result, completed_zone, row_id, data);
		mysql_free_result(mysql_result);
		pthread_rwlock_wrlock(&data->update_lock);
		if (data->saved_zone != NULL) {
			pfree(data->saved_zone->pool);
		}
		data->saved_zone = completed_zone;
        pthread_rwlock_unlock(&data->update_lock);
		continue_mysql:;
		mysql_close(db_conn);
		sleep(data->refresh_rate < 1 ? 1 : (unsigned int) data->refresh_rate);
	}
}

#endif
