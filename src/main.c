/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include "zone.h"
#include "accept.h"
#include "globals.h"
#include "tcp_network.h"
#include "mysql_zone.h"
#include "version.h"
#include "server.h"
#include "wake_thread.h"
#include <avuna/log.h>
#include <avuna/config.h>
#include <avuna/string.h>
#include <avuna/util.h>
#include <avuna/streams.h>
#include <avuna/pmem.h>
#include <avuna/pmem_hooks.h>
#include <avuna/queue.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/epoll.h>

struct udp_accept_param { // ;)
	int works_count;
	struct udpwork_param** works;
	int sfd;
};

struct udptcp_accept_param {
	int tcp;
	union param {
		struct accept_param* accept;
		struct udp_accept_param udp;
	} param;
};


int load_binding(struct config_node* bind_node, struct server_binding* binding) {
	const char* bind_mode = config_get(bind_node, "bind-mode");
	const char* bind_ip = NULL;
	uint16_t port = 0;
	const char* bind_file = NULL;
	int namespace;
	int bind_all = 0;
	int use_ipv6 = 0;
	int udp = 0;
	if (str_eq_case(bind_mode, "tcp") || (udp = str_eq_case(bind_mode, "udp"))) {
		binding->binding_type = (uint8_t) (udp ? BINDING_UDP4 : BINDING_TCP4);
		bind_ip = config_get(bind_node, "bind-ip");
		if (bind_ip == NULL || str_eq_case(bind_ip, "0.0.0.0")) {
			bind_all = 1;
		}
		use_ipv6 = bind_all || str_contains_case(bind_ip, ":");
		if (use_ipv6) {
			binding->binding_type = (uint8_t) (udp ? BINDING_UDP6 : BINDING_TCP6);
		}
		const char* bind_port = config_get(bind_node, "bind-port");
		if (bind_port != NULL && !str_isunum(bind_port)) {
			errlog(delog, "Invalid bind-port for binding: %s", bind_node->name);
			return 1;
		}
		port = (uint16_t) (bind_port == NULL ? 53 : strtoul(bind_port, NULL, 10));
		namespace = use_ipv6 ? PF_INET6 : PF_INET;
	} else {
		errlog(delog, "Invalid bind-mode for binding: %s", bind_node->name);
		return 1;
	}


	int server_fd = socket(namespace, udp ? SOCK_DGRAM : SOCK_STREAM, IPPROTO_UDP);
	if (server_fd < 0) {
		errlog(delog, "Error creating socket for binding: %s, %s", bind_node->name, strerror(errno));
		return 1;
	}
	phook(binding->pool, close_hook, (void*) server_fd);
	int one = 1;
	int zero = 0;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
		errlog(delog, "Error setting SO_REUSEADDR for binding: %s, %s", bind_node->name, strerror(errno));
		return 1;
	}
	sock:;

	if (binding->binding_type == BINDING_TCP6 || binding->binding_type == BINDING_UDP6) {
		if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &zero, sizeof(zero)) == -1) {
			errlog(delog, "Error unsetting IPV6_V6ONLY for binding: %s, %s", bind_node->name, strerror(errno));
			return 1;
		}
		binding->binding.in6.sin6_flowinfo = 0;
		binding->binding.in6.sin6_scope_id = 0;
		binding->binding.in6.sin6_family = AF_INET6;
		if (bind_all) binding->binding.in6.sin6_addr = in6addr_any;
		else if (!inet_pton(AF_INET6, bind_ip, &(binding->binding.in6.sin6_addr))) {
			errlog(delog, "Error binding socket for binding: %s, invalid bind-ip", bind_node->name);
			return 1;
		}
		binding->binding.in6.sin6_port = htons(port);
		if (bind(server_fd, (struct sockaddr*) &binding->binding.in6, sizeof(binding->binding.in6))) {
			if (bind_all) {
				binding->binding_type = BINDING_TCP4;
				goto sock;
			}
			errlog(delog, "Error binding socket for binding: %s, %s", bind_node->name, strerror(errno));
			return 1;
		}
	} else if (binding->binding_type == BINDING_TCP4 || binding->binding_type == BINDING_UDP4) {
		binding->binding.in4.sin_family = AF_INET;
		if (bind_all) binding->binding.in4.sin_addr.s_addr = INADDR_ANY;
		else if (!inet_aton(bind_ip, &(binding->binding.in4.sin_addr))) {
			errlog(delog, "Error binding socket for binding: %s, invalid bind-ip", bind_node->name);
			return 1;
		}
		binding->binding.in4.sin_port = htons(port);
		if (bind(server_fd, (struct sockaddr*) &binding->binding.in4, sizeof(binding->binding.in4))) {
			errlog(delog, "Error binding socket for binding: %s, %s", bind_node->name, strerror(errno));
			return 1;
		}
	} else {
		errlog(delog, "Invalid family for binding: %s", bind_node->name);
		return 1;
	}
	if (listen(server_fd, 50)) {
		errlog(delog, "Error listening on socket for binding: %s, %s", bind_node->name, strerror(errno));
		return 1;
	}
	if (binding->binding_type != BINDING_UDP4 && binding->binding_type != BINDING_UDP6 && fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL) | O_NONBLOCK) < 0) {
		errlog(delog, "Error setting non-blocking for binding: %s, %s", bind_node->name, strerror(errno));
		return 1;
	}
	binding->fd = server_fd;
	return 0;
}


int load_zone(struct config_node* node, struct server_zone* zone) {
	const char* type = config_get(node, "type");
	if (str_eq_case(type, "file")) {
		char* file = (char*) config_get(node, "file");
		if (file == NULL) {
			errlog(delog, "Invalid zone file for zone: %s", node->name);
			return 1;
		}
		int fd = open(file, O_CREAT | O_RDONLY, 0664);
		if (fd < 0) {
			errlog(delog, "Invalid zone file for zone %s: '%s' Error: %s", node->name, file, strerror(errno));
			return 1;
		}
		close(fd);
		struct zone* dns_zone = pmalloc(zone->pool, sizeof(struct zone));
		dns_zone->pool = zone->pool;
		dns_zone->domain = "@";
		if (zone_read(dns_zone, file, "/etc/avuna/dns/", delog) < 0) {
			errlog(delog, "Invalid zone file for zone: %s: '%s' Error: %s", node->name, file, strerror(errno));
			return 1;
		}
		zone->type = SERVER_ZONE_FILE;
		zone->data.file_zone = dns_zone;
	} else if (str_eq_case(type, "mysql")) {
#ifndef SUPPORTS_MYSQL
		errlog(delog, "Invalid zone %s: %s (mysql not supported by build)", node->name);
		return 1;
#else
		char* host = (char*) config_get(node, "host");
		if (host == NULL) {
			host = "localhost";
		}
		char* port_string = (char*) config_get(node, "port");
		if (port_string == NULL) {
			port_string = "3306";
		}
		if (!str_isunum(port_string)) {
			errlog(delog, "Invalid port for mysql zone: %s", node->name);
			return 1;
		}
		uint16_t port = strtoul(port_string, NULL, 10);
		char* refresh_string = (char*) config_get(node, "refresh-rate");
		if (refresh_string == NULL) {
			refresh_string = "60";
		}
		if (!str_isunum(refresh_string)) {
			errlog(delog, "Invalid refresh rate for mysql zone: %s", node->name);
			return 1;
		}
		size_t refresh_rate = strtoul(refresh_string, NULL, 10);
		char* username = (char*) config_get(node, "username");
		if (username == NULL) {
			errlog(delog, "Invalid username for mysql zone: %s", node->name);
			return 1;
		}
		char* password = (char*) config_get(node, "password");
		char* schema = (char*) config_get(node, "schema");
		if (schema == NULL) {
			schema = "dns";
		}
		struct mysql_zone* dns_zone = pcalloc(zone->pool, sizeof(struct mysql_zone));
		dns_zone->pool = zone->pool;
		dns_zone->host = host;
		dns_zone->port = port;
		dns_zone->refresh_rate = refresh_rate;
		dns_zone->username = username;
		dns_zone->password = password;
		dns_zone->schema = schema;
		dns_zone->zone = zone;
		zone->type = SERVER_ZONE_MYSQL;
		zone->data.mysql_zone = dns_zone;
#endif
	} else {
		return 1;
	}
	return 0;
}


int main(int argc, char* argv[]) {
	signal(SIGPIPE, SIG_IGN);
	if (getuid() != 0 || getgid() != 0) {
		printf("Must run as root!\n");
		return 1;
	}
	global_pool = mempool_new();
	printf("Loading Avuna %s %s\n", DAEMON_NAME, VERSION);
#ifdef DEBUG
	printf("Running in Debug mode!\n");
#endif
	char cwd[256];
	if (argc == 1) {
		memcpy(cwd, "/etc/avuna/", 11);
		cwd[11] = 0;
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME) + 1, 0, global_pool);
		strcat(cwd, str_tolower(dn));
	} else {
		size_t l = strlen(argv[1]);
		if (argv[1][l - 1] == '/') argv[1][--l] = 0;
		memcpy(cwd, argv[1], l + 1);
	}
	recur_mkdir(cwd, 0750);
	chdir(cwd);
	if (strlen(cwd) > 240) {
		printf("Load Directory is more than 240 characters path length!\n");
		return 1;
	}
	strncat(cwd, "/main.cfg", 9);
	cfg = config_load(cwd);
	if (cfg == NULL) {
		printf("Error loading Config<%s>: %s\n", cwd, errno == EINVAL ? "File doesn't exist!" : strerror(errno));
		return 1;
	}
	struct config_node* daemon = config_get_unique_cat(cfg, "daemon");
	if (daemon == NULL) {
		printf("[daemon] block does not exist in %s!\n", cwd);
		return 1;
	}
#ifndef DEBUG
	int runn = 0;
	pid_t pid = 0;
	char* pid_file = (char*) config_get(daemon, "pid-file");
	if (!access(pid_file, F_OK)) {
		int pidfd = open(pid_file, O_RDONLY);
		if (pidfd < 0) {
			printf("Failed to open PID file! %s\n", strerror(errno));
			return 1;
		}
		char pidr[16];
		if (readLine(pidfd, pidr, 16) >= 1) {
			pid = (pid_t) strtoul(pidr, NULL, 10);
			int k = kill(pid, 0);
			if (k == 0) {
				runn = 1;
			}
		} else {
			printf("Failed to read PID file! %s\n", strerror(errno));
			return 1;
		}
		close(pidfd);
	}
	if (runn) {
		printf("Already running! PID = %i\n", pid);
		exit(0);
	} else {
		pid_t f = fork();
		if (f > 0) {
			printf("Daemonized! PID = %i\n", f);

			exit(0);
		} else {
			printf("Now running as daemon!\n");
			if (setsid() < 0) {
				printf("Failed to exit process tree: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "r", stdin) < 0) {
				printf("reopening of STDIN to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stderr) < 0) {
				printf("reopening of STDERR to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stdout) < 0) {
				printf("reopening of STDOUT to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
		}
	}
#else
	printf("Daemonized! PID = %i\n", getpid());
#endif
	delog = pmalloc(global_pool, sizeof(struct logsess));
	delog->pi = 0;
	delog->access_fd = NULL;
	const char* el = config_get(daemon, "error-log");
	delog->error_fd = el == NULL ? NULL : fopen(el, "a"); // fopen will return NULL on error, which works.
#ifndef DEBUG
	pid_file = str_dup(pid_file, 1, global_pool);
	for (size_t i = strlen(pid_file) - 1; i--; i >= 0) {
		if (pid_file[i] == '/') {
			pid_file[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pid, 0750) == -1) {
		errlog(delog, "Error making directories for PID file: %s.", strerror(errno));
		return 1;
	}

	FILE *pfd = fopen(pid_file, "w");
	if (pfd == NULL) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
#endif
	struct hashmap* binding_map = hashmap_new(16, global_pool);

	struct list* binding_list = hashmap_get(cfg->nodeListsByCat, "binding");
	for (int i = 0; i < binding_list->count; i++) {
		struct config_node* bind_node = binding_list->data[i];
		if (bind_node->name == NULL) {
			errlog(delog, "All bind nodes must have names, skipping node.");
			continue;
		}
		struct mempool* pool = mempool_new();
		struct server_binding* binding = pmalloc(pool, sizeof(struct server_binding));
		binding->pool = pool;

		if (load_binding(bind_node, binding)) {
			pfree(binding->pool);
		} else {
			hashmap_put(binding_map, bind_node->name, binding);
		}
	}

	struct hashmap* zone_map = hashmap_new(16, global_pool);

	struct list* zone_list = hashmap_get(cfg->nodeListsByCat, "zone");
	for (int i = 0; i < zone_list->count; i++) {
		struct config_node* zone_node = zone_list->data[i];
		if (zone_node->name == NULL) {
			errlog(delog, "All zone nodes must have names, skipping node.");
			continue;
		}
		struct mempool* pool = mempool_new();
		struct server_zone* zone = pmalloc(pool, sizeof(struct server_zone));
		zone->pool = pool;

		if (load_zone(zone_node, zone)) {
			pfree(zone->pool);
		} else {
			hashmap_put(zone_map, zone_node->name, zone);
		}
	}


	struct list* server_list = hashmap_get(cfg->nodeListsByCat, "server");
	struct list* server_infos = list_new(8, global_pool);

	for (size_t i = 0; i < server_list->count; i++) {
		struct config_node* serv = server_list->data[i];
		if (serv->name == NULL) {
			errlog(delog, "All server nodes must have names, skipping node.");
			continue;
		}
		struct mempool* pool = mempool_new();
		struct server_info* info = pmalloc(pool, sizeof(struct server_info));
		info->id = serv->name;
		info->pool = pool;
		info->bindings = list_new(8, info->pool);
		info->prepared_connections = queue_new(0, 1, info->pool);
		list_append(server_infos, info);
		const char* bindings = config_get(serv, "bindings");
		struct list* binding_names = list_new(8, info->pool);
		char bindings_dup[strlen(bindings) + 1];
		strcpy(bindings_dup, bindings);
		str_split(bindings_dup, ",", binding_names);

		for (size_t j = 0; j < binding_names->count; ++j) {
			char* name_trimmed = str_trim(binding_names->data[j]);
			struct server_binding* data = hashmap_get(binding_map, name_trimmed);
			if (data == NULL) {
				errlog(delog, "Invalid binding name for server: %s, %s", serv->name, name_trimmed);
				continue;
			}
			list_append(info->bindings, data);
		}

		char* zone_name = (char*) config_get(serv, "zone");
		if (zone_name == NULL) {
			errlog(delog, "No zone name for server: %s", serv->name);
			continue;
		}
		char zones_dup[strlen(bindings) + 1];
		strcpy(zones_dup, bindings);
		zone_name = str_trim(zones_dup);
		struct server_zone* zone = hashmap_get(zone_map, zone_name);
		if (zone == NULL || zone->server != NULL) {
			errlog(delog, "Invalid zone name for server: %s, %s", serv->name, zone_name);
			continue;
		}
		zone->server = info;
		info->zone = zone;

		const char* tcc = config_get(serv, "threads");
		if (!str_isunum(tcc)) {
			errlog(delog, "Invalid threads for server: %s", serv->name);
			continue;
		}
		ssize_t tc = strtoul(tcc, NULL, 10);
		if (tc < 1 || tc > 128) {
			errlog(delog, "Invalid threads for server: %s, must be greater than 1 and less than 128.\n", serv->name);
			continue;
		}
		info->max_worker_count = (uint16_t) tc;

		struct logsess* slog = pmalloc(info->pool, sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = config_get(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
		const char* lel = config_get(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
		acclog(slog, "Server %s listening for connections!", serv->name);
		info->logsess = slog;
	}


	/*int servsl;
	struct config_node** servs = hashmap_get(cfg->nodeListsByCat, "server");
	int sr = 0;
	struct udptcp_accept_param aps[servsl];
	for (int i = 0; i < servsl; i++) {

		const char* zone = getConfigValue(serv, "master-zone");
		int zfd = -1;
		if (streq_nocase(zone, "mysql")) {

		} else if (zone == NULL || (zfd = open(zone, O_CREAT | O_RDONLY, 0664)) < 0) {
			if (serv->id != NULL) errlog(delog, "Invalid master-zone for server: %s", serv->id);
			else errlog(delog, "Invalid master-zone for server");
			close (sfd);
			continue;
		}
		if (zfd >= 0) close(zfd);
		if (propo == SOCK_STREAM) {
			struct accept_param* ap = xmalloc(sizeof(struct accept_param));
			if (serv->id != NULL) acclog(slog, "Server %s listening for connections!", serv->id);
			else acclog(slog, "Server listening for connections!");
			ap->port = port;
			ap->zone = zonep;
			ap->server_fd = sfd;
			ap->config = serv;
			ap->works_count = tc;
			ap->works = xmalloc(sizeof(struct work_param*) * tc);
			ap->logsess = slog;
			struct udptcp_accept_param is_psuedo_type;
			is_psuedo_type.tcp = 1;
			is_psuedo_type.param.accept = ap;
			aps[i] = is_psuedo_type;
		} else {
			if (serv->id != NULL) acclog(slog, "Server %s listening!", serv->id);
			else acclog(slog, "Server listening!");
			struct udptcp_accept_param is_psuedo_type;
			is_psuedo_type.tcp = 0;
			struct udp_accept_param uap;
			uap.works = xmalloc(sizeof(struct udpwork_param*) * tc);
			uap.works_count = tc;
			uap.sfd = sfd;
			is_psuedo_type.param.udp = uap;
			aps[i] = is_psuedo_type;
		}
		struct mysql_zone* mysql_zone = xmalloc(sizeof(struct mysql_zone));
		mysql_zone->mysql = mysql;
		mysql_zone->host = host;
		mysql_zone->port = port;
		mysql_zone->username = username;
		mysql_zone->password = password;
		mysql_zone->schema = schema;
		mysql_zone->completed_zone = NULL;
		mysql_zone->refresh_rate = refresh_rate;
		mysql_zone->complete = 0;
		mysql_zone->saved_zone = NULL;
		//thrs = new_collection(0);
#ifdef SUPPORTS_MYSQL
		if (mysql) {
			pthread_t ptx;
			int pc = pthread_create(&ptx, NULL, mysql_thread, mysql_zone);
			if (pc) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, mysql will not update @ %s server.", pc, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, mysql will not update.", pc);
			}
		}
#endif
		for (int x = 0; x < tc; x++) {
			if (propo == SOCK_STREAM) {
				struct work_param* wp = xmalloc(sizeof(struct work_param));
				wp->conns = new_collection(mc < 1 ? 0 : mc / tc);
				wp->logsess = slog;
				wp->i = x;
				wp->sport = port;
				wp->zone = zonep;
				wp->mysql = mysql_zone;
				aps[i].param.accept->works[x] = wp;
			} else {
				struct udpwork_param* uwp = xmalloc(sizeof(struct udpwork_param));
				uwp->logsess = slog;
				uwp->i = x;
				uwp->sfd = sfd;
				uwp->zone = zonep;
				uwp->mysql = mysql_zone;
				aps[i].param.udp.works[x] = uwp;
			}
		}
		sr++;
	}*/
	const char* uids = config_get(daemon, "uid");
	const char* gids = config_get(daemon, "gid");
	uid_t uid = (uid_t) (uids == NULL ? 0 : strtoul(uids, NULL, 10));
	uid_t gid = (uid_t) (gids == NULL ? 0 : strtoul(gids, NULL, 10));
	if (gid > 0) {
		if (setgid(gid) != 0) {
			errlog(delog, "Failed to setgid! %s", strerror(errno));
		}
	}
	if (uid > 0) {
		if (setuid(uid) != 0) {
			errlog(delog, "Failed to setuid! %s", strerror(errno));
		}
	}
	acclog(delog, "Running as UID = %u, GID = %u, starting workers.", getuid(), getgid());
	for (size_t i = 0; i < server_infos->count; ++i) {
		struct server_info* server = server_infos->data[i];

#ifdef SUPPORTS_MYSQL
		if (server->zone->type == SERVER_ZONE_MYSQL) {
			pthread_t ptx;
			int pc = pthread_create(&ptx, NULL, (void* (*)(void*)) mysql_thread, server->zone->data.mysql_zone);
			if (pc) {
				errlog(delog, "Error creating thread: pthread errno = %i, mysql will not update @ %s server.", pc, server->id);
			}
		}
#endif


		for (size_t j = 0; j < server->bindings->count; ++j) {
			struct accept_param* param = pmalloc(server->pool, sizeof(struct accept_param));
			param->server = server;
			param->binding = server->bindings->data[j];
			pthread_t pt;
			int pthread_err = pthread_create(&pt, NULL, (void*) run_accept, param);
			if (pthread_err != 0) {
				errlog(delog, "Error creating accept thread: pthread errno = %i.", pthread_err);
				continue;
			}
		}

		struct list* works = list_new(server->max_worker_count, server->pool);

		for (size_t j = 0; j < server->max_worker_count; ++j) {
			struct work_param* param = pmalloc(server->pool, sizeof(struct work_param));
			param->i = j;
			param->server = server;
			param->epoll_fd = epoll_create1(0);
			if (param->epoll_fd < 0) {
				errlog(param->server->logsess, "Failed to create epoll fd! %s", strerror(errno));
				continue;
			}
			pthread_t pt;
			int pthread_err = pthread_create(&pt, NULL, (void*) run_tcp_network, param);
			if (pthread_err != 0) {
				errlog(delog, "Error creating work thread: pthread errno = %i.", pthread_err);
				continue;
			}
			list_append(works, param);
		}

		struct wake_thread_arg* wt_arg = pmalloc(server->pool, sizeof(struct wake_thread_arg));
		wt_arg->work_params = works;
		wt_arg->server = server;

		pthread_t pt;
		int pthread_err = pthread_create(&pt, NULL, (void*) wake_thread, wt_arg);
		if (pthread_err != 0) {
			errlog(delog, "Error creating work thread: pthread errno = %i.", pthread_err);
			continue;
		}

	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
	while (1) {
		sleep(60);
	}
#pragma clang diagnostic pop
	return 0;
}
