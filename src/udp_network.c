//
// Created by p on 4/9/19.
//

#include "udp_network.h"
#include "tcp_network.h"
#include "dns_resolver.h"
#include "../lib/include/avuna/dns.h"
#include "server.h"
#include <avuna/pmem.h>
#include <netinet/in.h>


void run_udp_network(struct accept_param* param) {
    struct mempool* pool = mempool_new();
    unsigned char* message_buf = pmalloc(pool, 512); // udp has a maximum of 512
    struct sockaddr_in6 addr;
    socklen_t addrl = sizeof(struct sockaddr_in6);
    struct zone* active_zone = NULL;
    if (param->server->zone->type == SERVER_ZONE_FILE) {
        active_zone = param->server->zone->data.file_zone;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while (1) {
        ssize_t x = recvfrom(param->binding->fd, message_buf, 512, 0, (struct sockaddr*) &addr, &addrl);
        if (x < 0) continue;
        if (x > 0) {
            int mysql = param->server->zone->type == SERVER_ZONE_MYSQL;
            if (mysql) {
                pthread_rwlock_rdlock(&param->server->zone->data.mysql_zone->update_lock);
                active_zone = param->server->zone->data.mysql_zone->saved_zone;
            }
            if (active_zone == NULL) {
                if (mysql) {
                    pthread_rwlock_unlock(&param->server->zone->data.mysql_zone->update_lock);
                }
                continue;
            }
            struct mempool* query_pool = mempool_new();
            struct dns_query* query = dns_parse(query_pool, message_buf, x);
            dns_respond_query(query_pool, query, active_zone);
            uint8_t* out_buf = NULL;
            ssize_t serialized_length = dns_serialize(query_pool, query, &out_buf, 1);
            if (serialized_length > 0) {
                // sendto can fail, but what we do regardless is cleanup
                sendto(param->binding->fd, out_buf, (size_t) serialized_length, 0, (const struct sockaddr*) &addr, addrl);
                dns_report((struct sockaddr*) &addr, query, param->server->logsess);
            }
            if (mysql) {
                pthread_rwlock_unlock(&param->server->zone->data.mysql_zone->update_lock);
            }
            pfree(query_pool);
        }
    }
#pragma clang diagnostic pop
    pfree(pool);
}
