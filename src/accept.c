/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#include "accept.h"
#include "tcp_network.h"
#include "connection.h"
#include <avuna/pmem.h>
#include <avuna/pmem_hooks.h>
#include <avuna/string.h>
#include <avuna/buffer.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>

void run_accept(struct accept_param* param) {
	static int one = 1;
	struct timeval timeout;
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	struct pollfd spfd;
	spfd.events = POLLIN;
	spfd.revents = 0;
	spfd.fd = param->binding->fd;
	while (1) {
		struct mempool* pool = mempool_new();
		struct conn* conn = pmalloc(pool, sizeof(struct conn));
		conn->pool = pool;
		memset(&conn->addr, 0, sizeof(struct sockaddr_in6));
		conn->addrlen = sizeof(struct sockaddr_in6);
		buffer_init(&conn->read_buffer, conn->pool);
		buffer_init(&conn->write_buffer, conn->pool);
		conn->state = 0;
		repoll:;
		if (poll(&spfd, 1, -1) < 0) {
			errlog(param->server->logsess, "Error while polling server: %s", strerror(errno));
			pfree(conn->pool);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			errlog(param->server->logsess, "Error after polling server: %i (poll revents)", spfd.revents);
			pfree(conn->pool);
			break;
		}
		spfd.revents = 0;
		int cfd = accept(param->binding->fd, (struct sockaddr*) &conn->addr, &conn->addrlen);
		if (cfd < 0) {
			if (errno == EAGAIN) {
				goto repoll;
			}
			errlog(param->server->logsess, "Error while accepting client: %s", strerror(errno));
			pfree(conn->pool);
			continue;
		}
		conn->fd = cfd;
		phook(conn->pool, close_hook, (void*) conn->fd);
		if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting recv timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting send timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void *) &one, sizeof(one))) printf("Setting TCP_NODELAY failed! %s\n", strerror(errno));
		if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
			errlog(param->server->logsess, "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.\n", strerror(errno));
			pfree(conn->pool);
			continue;
		}
		queue_push(param->server->prepared_connections, conn);
	}
}
