/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#include "accept.h"
#include "util.h"
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include "xstring.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include "work.h"
#include <unistd.h>
#include "tls.h"

void run_accept(struct accept_param* param) {
	static int one = 1;
	static unsigned char onec = 1;
	struct timeval timeout;
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	struct pollfd spfd;
	spfd.events = POLLIN;
	spfd.revents = 0;
	spfd.fd = param->server_fd;
	while (1) {
		struct conn* c = xmalloc(sizeof(struct conn));
		memset(&c->addr, 0, sizeof(struct sockaddr));
		c->addrlen = sizeof(struct sockaddr);
		c->readBuffer = NULL;
		c->readBuffer_size = 0;
		c->readBuffer_checked = 0;
		c->writeBuffer = NULL;
		c->writeBuffer_size = 0;
		c->postLeft = 0;
		c->handshaked = 0;
		if (param->cert != NULL) {
			gnutls_init(&c->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
			gnutls_priority_set(c->session, param->cert->priority);
			gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, param->cert->cert);
			gnutls_certificate_server_set_request(c->session, GNUTLS_CERT_IGNORE);
			c->tls = 1;
		} else {
			c->tls = 0;
		}
		if (poll(&spfd, 1, -1) < 0) {
			printf("Error while polling server: %s\n", strerror(errno));
			xfree(c);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			printf("Error after polling server: %i (poll revents), closing server!\n", spfd.revents);
			xfree(c);
			close(param->server_fd);
			break;
		}
		spfd.revents = 0;
		int cfd = accept(param->server_fd, &c->addr, &c->addrlen);
		if (cfd < 0) {
			if (errno == EAGAIN) continue;
			printf("Error while accepting client: %s\n", strerror(errno));
			xfree(c);
			continue;
		}
		c->fd = cfd;
		if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting recv timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting send timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void *) &one, sizeof(one))) printf("Setting TCP_NODELAY failed! %s\n", strerror(errno));
		if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
			printf("Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.\n", strerror(errno));
			close(cfd);
			continue;
		}
		if (param->cert != NULL) {
			gnutls_transport_set_int2(c->session, cfd, cfd);
			/*if (sniCallback != NULL) {
			 struct sni_data* ld = xmalloc(sizeof(struct sni_data));
			 ld->this = this;
			 ld->sniCallback = sniCallback;
			 lsd = ld;
			 gnutls_handshake_set_post_client_hello_function(sessiond, handleSNI);
			 }*/
			int r = gnutls_handshake(c->session);
			if (gnutls_error_is_fatal(r)) {
				gnutls_deinit(c->session);
				close(c->fd);
				xfree(c);
				continue;
			} else if (r == GNUTLS_E_SUCCESS) {
				c->handshaked = 1;
			}
		}
		struct work_param* work = param->works[rand() % param->works_count];
		if (add_collection(work->conns, c)) { // TODO: send to lowest load, not random
			if (errno == EINVAL) {
				printf("Too many open connections! Closing client.\n");
			} else {
				printf("Collection failure! Closing client. %s\n", strerror(errno));
			}
			close(cfd);
			continue;
		}
		if (write(work->pipes[1], &onec, 1) < 1) {
			printf("Failed to write to wakeup pipe! Things may slow down. %s\n", strerror(errno));
		}
	}
}
