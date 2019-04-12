//
// Created by p on 3/23/19.
//

#include "tcp_network.h"
#include "wake_thread.h"
#include <avuna/queue.h>
#include <avuna/log.h>
#include <avuna/llist.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <string.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

void wake_thread(struct wake_thread_arg* arg) {
    size_t counter = 0;
    while (1) {
        struct conn* conn = queue_pop(arg->server->prepared_connections);
        struct work_param* param = arg->work_params->data[counter];
        counter = (counter + 1) % arg->work_params->count;
        struct epoll_event event;
        event.events = EPOLLIN | EPOLLOUT | EPOLLET;
        event.data.ptr = conn;
        if (epoll_ctl(param->epoll_fd, EPOLL_CTL_ADD, conn->fd, &event)) {
            errlog(param->server->logsess, "Failed to add fd to epoll! %s", strerror(errno));
            continue;
        }
    }
}

#pragma clang diagnostic pop