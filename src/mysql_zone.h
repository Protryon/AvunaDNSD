/*
 * mysql.h
 *
 *  Created on: Jun 19, 2016
 *      Author: root
 */

#ifndef NOSUPPORTS_MYSQL

#ifndef MYSQL_PARSER_H_
#define MYSQL_PARSER_H_

#include "globals.h"
#include "zone.h"
#include "server.h"
#include <avuna/pmem.h>


struct mysql_zone {
    struct mempool* pool;
    char* host;
    uint16_t port;
    char* username;
    char* password;
    char* schema;
    size_t refresh_rate;
    struct zone* saved_zone;
    struct zone* backup_zone;
    struct server_zone* zone;
};

void mysql_thread(struct mysql_zone* data);

#endif /* MYSQL_PARSER_H_ */

#endif
