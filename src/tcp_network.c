/*
 * work.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#include "tcp_network.h"
#include "accept.h"
#include "server.h"
#include "connection.h"
#include "dns_resolver.h"
#include <avuna/string.h>
#include <avuna/util.h>
#include <avuna/streams.h>
#include <avuna/log.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <stdint.h>

int handleRead(struct conn* conn, struct work_param* param, struct zone* zone) {
	if (conn->read_buffer.size >= 2) {
		uint16_t len = 0;
		buffer_peek(&conn->read_buffer, 2, (uint8_t*) &len);
		uint16_t packet_length = htons(len);
		if (packet_length > 2048) { // 2 KB max
			return 1;
		}
		if (conn->read_buffer.size >= 2 + packet_length) {
			conn->state = 1;
			struct mempool* query_pool = mempool_new();
			uint8_t* total_packet = pmalloc(query_pool, 2 + packet_length);
			buffer_pop(&conn->read_buffer, 2 + packet_length, total_packet);
			total_packet += 2;
			struct dns_query* query = dns_parse(query_pool, total_packet, packet_length);
			dns_respond_query(query_pool, query, zone);
			uint8_t* out_buf = NULL;
			ssize_t serialized_length = dns_serialize(conn->pool, query, &out_buf, 0);
			if (serialized_length > 0) {
				buffer_push(&conn->write_buffer, out_buf, (size_t) serialized_length);
				dns_report((struct sockaddr*) &conn->addr, query, param->server->logsess);
				if (trigger_write(conn)) {
					return 1;
				}
			}
			pfree(query_pool);
		}
	}
	return 0;
}

int trigger_write(struct conn* conn) {
	if (conn->write_available && conn->write_buffer.size > 0) {
		for (struct llist_node* node = conn->write_buffer.buffers->head; node != NULL; ) {
			struct buffer_entry* entry = node->data;
			ssize_t mtr = write(conn->fd, entry->data, entry->size);
			size_t written = (size_t) mtr;
			if (written < entry->size) {
				entry->data += written;
				entry->size -= written;
				conn->write_available = 1;
				conn->write_buffer.size -= written;
				break;
			} else {
				conn->write_buffer.size -= written;
				pprefree_strict(conn->write_buffer.pool, entry->data_root);
				struct llist_node* next = node->next;
				llist_del(conn->write_buffer.buffers, node);
				node = next;
				if (node == NULL) {
					conn->write_available = 1;
					break;
				} else {
					continue;
				}
			}
		}
	}
	return conn->state == 1 && conn->write_buffer.size == 0;
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
void run_tcp_network(struct work_param* param) {
	struct mempool* pool = mempool_new();
	struct epoll_event* events = pmalloc(pool, 1024 * sizeof(struct epoll_event));
	struct zone* active_zone = NULL;
	if (param->server->zone->type == SERVER_ZONE_FILE) {
		active_zone = param->server->zone->data.file_zone;
	}
	while (1) {
		int event_count = epoll_wait(param->epoll_fd, events, 1024, -1);
		if (param->server->zone->type == SERVER_ZONE_MYSQL && param->server->zone->data.mysql_zone->complete && active_zone != param->server->zone->data.mysql_zone->completed_zone) {
			active_zone = param->server->zone->data.mysql_zone->completed_zone;
		}
		if (event_count < 0) {
			printf("Epoll error in worker thread! %s\n", strerror(errno));
		} else if (event_count == 0) continue;
		for (int i = 0; i < event_count; i++) {
			int event = events[i].events;
			struct conn* conn = events[i].data.ptr;
			if (conn == NULL || event == 0) continue;
			if (event & EPOLLERR) {
				pfree(conn->pool);
				continue;
			}
			if (event & EPOLLHUP) {
				pfree(conn->pool);
				continue;
			}

			if (event & EPOLLOUT) {
				conn->write_available = 1;
				if (trigger_write(conn)) {
					pfree(conn->pool);
					continue;
				}
			}
			if (event & EPOLLIN) {
				size_t tr = 0;
				ioctl(conn->fd, FIONREAD, &tr);
				++tr;
				if (tr < 16) {
					tr = 16;
				}
				uint8_t* buf = pmalloc(conn->pool, tr);
				size_t r = 0;
				while (r < tr) {
					ssize_t x = read(conn->fd, buf + r, tr - r);
					if (x <= 0) {
						if (errno == EAGAIN) {
							break;
						}
						pfree(conn->pool);
						continue;
					}
					r += x;
				}
				int p = handleRead(conn, param, active_zone);
				if (p == 1) {
					pfree(conn->pool);
					continue;
				}
			}
		}
	}
	pfree(pool);
}
#pragma clang diagnostic pop
