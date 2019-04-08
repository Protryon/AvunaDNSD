/*
 * udpwork.h
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#ifndef UDPWORK_H_
#define UDPWORK_H_

#include "log.h"
#include <netinet/in.h>
#include "zone.h"
#include "accept.h"

struct udpwork_param {
		struct logsess* logsess;
		int i;
		int sfd;
		struct zone* zone;
		struct mysql_data* mysql;
};

struct mysql_data {
		int mysql;
		char* mysql_host;
		int mysql_port;
		char* mysql_user;
		char* mysql_pass;
		char* mysql_schema;
		int complete;
		struct zone* czone;
		struct zone* szone;
		int mysql_refresh;
};

void writeDomain(int compress, char* dom, unsigned char* buf, size_t dlx, size_t ml, size_t* cs);
void run_udpwork(struct udpwork_param* param);
void handleUDP(struct mysql_data* mysql, struct logsess* log, struct zone* zone, int sfd, void* buf, size_t len, struct sockaddr* addr, socklen_t addrl, struct conn* conn);

#endif /* UDPWORK_H_ */
