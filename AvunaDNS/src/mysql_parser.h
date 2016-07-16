/*
 * mysql.h
 *
 *  Created on: Jun 19, 2016
 *      Author: root
 */

#include "globals.h"
#ifdef SUPPORTS_MYSQL

#ifndef MYSQL_PARSER_H_
#define MYSQL_PARSER_H_

#include "udpwork.h"

void mysql_thread(struct mysql_data* data);

#endif /* MYSQL_PARSER_H_ */

#endif
