/*
 * udpwork.h
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#ifndef UDPWORK_H_
#define UDPWORK_H_

#include "log.h"

struct udpwork_param {
		struct logsess* logsess;
		int i;
		int sfd;
		struct zone* zone;
};
void writeDomain(char* dom, unsigned char* buf, size_t ml, size_t* cs);
void run_udpwork(struct udpwork_param* param);

#endif /* UDPWORK_H_ */
