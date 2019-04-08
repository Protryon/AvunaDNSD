/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include "accept.h"
#include "udpwork.h"
#include <avuna/log.h>


struct work_param {
		struct collection* conns;
		int pipes[2];
		struct logsess* logsess;
		int i;
		int sport;
		struct zone* zone;
		struct mysql_data* mysql;
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
