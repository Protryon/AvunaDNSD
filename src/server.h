//
// Created by p on 4/8/19.
//

#ifndef AVUNA_DNSD_SERVER_H
#define AVUNA_DNSD_SERVER_H

#include "mysql_zone.h"
#include <avuna/pmem.h>
#include <avuna/queue.h>
#include <stdint.h>

#define BINDING_TCP4 0
#define BINDING_TCP6 1
#define BINDING_UDP4 2
#define BINDING_UDP6 2

struct server_binding {
    struct mempool* pool;
    uint8_t binding_type;
    union {
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
    } binding;
    int fd;
};

#define SERVER_ZONE_FILE 0
#define SERVER_ZONE_MYSQL 1

struct server_zone {
    struct mempool* pool;
    struct server_info* server;
    uint8_t type;
    union {
        struct zone* file_zone;
        struct mysql_zone* mysql_zone;
    } data;
};

struct server_info {
    char* id;
    struct mempool* pool;
    struct list* bindings;
    struct server_zone* zone;
    struct logsess* logsess;
    uint16_t max_worker_count;
    struct queue* prepared_connections;
};

#endif //AVUNA_DNSD_SERVER_H
