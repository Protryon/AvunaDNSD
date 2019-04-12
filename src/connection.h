//
// Created by p on 4/9/19.
//

#ifndef AVUNA_DNSD_CONNECTION_H
#define AVUNA_DNSD_CONNECTION_H

#include <avuna/pmem.h>
#include <avuna/buffer.h>
#include <sys/socket.h>
#include <netinet/ip6.h>

struct conn {
    int fd;
    struct mempool* pool;
    union {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } addr;
    socklen_t addrlen;
    struct buffer read_buffer;
    struct buffer write_buffer;
    int state;
    int write_available;
};


#endif //AVUNA_DNSD_CONNECTION_H
