/*
 * accept.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef ACCEPT_H_
#define ACCEPT_H_

#include "tcp_network.h"
#include "server.h"
#include <sys/socket.h>
#include <netinet/ip6.h>

struct accept_param {
	struct server_info* server;
	struct server_binding* binding;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
