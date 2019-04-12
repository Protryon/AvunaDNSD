/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include "accept.h"
#include "connection.h"
#include <avuna/log.h>

struct work_param {
	size_t i;
	struct server_info* server;
	int epoll_fd;
};

int trigger_write(struct conn* conn);

void run_tcp_network(struct work_param* param);

#endif /* WORK_H_ */
