/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include "zone.h"
#include "udpwork.h"
#include "accept.h"
#include "globals.h"
#include "work.h"
#include "mysql_parser.h"
#include "version.h"
#include <avuna/log.h>
#include <avuna/config.h>
#include <avuna/string.h>
#include <avuna/util.h>
#include <avuna/streams.h>
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

int main(int argc, char* argv[]) {
	signal(SIGPIPE, SIG_IGN);
	if (getuid() != 0 || getgid() != 0) {
		printf("Must run as root!\n");
		return 1;
	}
	printf("Loading Avuna %s %s\n", DAEMON_NAME, VERSION);
#ifdef DEBUG
	printf("Running in Debug mode!\n");
#endif
	char cwd[256];
	if (argc == 1) {
		memcpy(cwd, "/etc/avuna/", 11);
		cwd[11] = 0;
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME) + 1, 0);
		strcat(cwd, str_tolower(dn));
		xfree(dn);
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
	struct cnode* dm = getUniqueByCat(cfg, CAT_DAEMON);
	if (dm == NULL) {
		printf("[daemon] block does not exist in %s!\n", cwd);
		return 1;
	}
	int runn = 0;
	pid_t pid = 0;
	const char* pid_file = getConfigValue(dm, "pid-file");
	if (!access(pid_file, F_OK)) {
		int pidfd = open(pid_file, O_RDONLY);
		if (pidfd < 0) {
			printf("Failed to open PID file! %s\n", strerror(errno));
			return 1;
		}
		char pidr[16];
		if (readLine(pidfd, pidr, 16) >= 1) {
			pid = atol(pidr);
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
#ifndef DEBUG
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
	delog = xmalloc(sizeof(struct logsess));
	delog->pi = 0;
	delog->access_fd = NULL;
	const char* el = getConfigValue(dm, "error-log");
	delog->error_fd = el == NULL ? NULL : fopen(el, "a"); // fopen will return NULL on error, which works.
	int pfpl = strlen(pid_file);
	char* pfp = xcopy(pid_file, pfpl + 1, 0);
	for (int i = pfpl - 1; i--; i >= 0) {
		if (pfp[i] == '/') {
			pfp[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pfp, 0750) == -1) {
		errlog(delog, "Error making directories for PID file: %s.", strerror(errno));
		return 1;
	}
//TODO: chown group to de-escalated
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
	int servsl;
	struct cnode** servs = getCatsByCat(cfg, CAT_SERVER, &servsl);
	int sr = 0;
	struct udptcp_accept_param aps[servsl];
	for (int i = 0; i < servsl; i++) {
		struct cnode* serv = servs[i];
		const char* bind_mode = getConfigValue(serv, "bind-mode");
		const char* bind_ip = NULL;
		int port = -1;
		const char* bind_file = NULL;
		int namespace = -1;
		int propo = SOCK_STREAM;
		int ba = 0;
		int ip6 = 0;
		if (streq(bind_mode, "tcp")) {
			bind_ip = getConfigValue(serv, "bind-ip");
			if (streq(bind_ip, "0.0.0.0")) {
				ba = 1;
			}
			ip6 = ba || contains(bind_ip, ":");
			const char* bind_port = getConfigValue(serv, "bind-port");
			if (!strisunum(bind_port)) {
				if (serv->id != NULL) errlog(delog, "Invalid bind-port for server: %s", serv->id);
				else errlog(delog, "Invalid bind-port for server.");
				continue;
			}
			port = atoi(bind_port);
			namespace = ip6 ? PF_INET6 : PF_INET;;
		} else if (streq(bind_mode, "unix")) {
			bind_file = getConfigValue(serv, "bind-file");
			namespace = PF_LOCAL;
		} else if (streq(bind_mode, "udp")) {
			bind_ip = getConfigValue(serv, "bind-ip");
			if (streq(bind_ip, "0.0.0.0")) {
				ba = 1;
			}
			ip6 = ba || contains(bind_ip, ":");
			const char* bind_port = getConfigValue(serv, "bind-port");
			if (!strisunum(bind_port)) {
				if (serv->id != NULL) errlog(delog, "Invalid bind-port for server: %s", serv->id);
				else errlog(delog, "Invalid bind-port for server.");
				continue;
			}
			port = atoi(bind_port);
			namespace = ip6 ? PF_INET6 : PF_INET;;
			propo = SOCK_DGRAM;
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid bind-mode for server: %s", serv->id);
			else errlog(delog, "Invalid bind-mode for server.");
			continue;
		}
		const char* tcc = getConfigValue(serv, "threads");
		if (!strisunum(tcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s", serv->id);
			else errlog(delog, "Invalid threads for server.");
			continue;
		}
		int tc = atoi(tcc);
		if (tc < 1) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s, must be greater than 1.", serv->id);
			else errlog(delog, "Invalid threads for server, must be greater than 1.");
			continue;
		}
		const char* mcc = getConfigValue(serv, "max-conn");
		if (propo == SOCK_STREAM && !strisunum(mcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-conn for server: %s", serv->id);
			else errlog(delog, "Invalid max-conn for server.");
			continue;
		}
		int mc = propo != SOCK_STREAM ? 0 : atoi(mcc);
		sock: ;
		int sfd = socket(namespace, propo, 0);
		if (sfd < 0) {
			if (serv->id != NULL) errlog(delog, "Error creating socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error creating socket for server, %s", strerror(errno));
			continue;
		}
		int one = 1;
		int zero = 0;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
			if (serv->id != NULL) errlog(delog, "Error setting SO_REUSEADDR for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting SO_REUSEADDR for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (namespace == PF_INET || namespace == PF_INET6) {
			if (ip6) {
				if (setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &zero, sizeof(zero)) == -1) {
					if (serv->id != NULL) errlog(delog, "Error unsetting IPV6_V6ONLY for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error unsetting IPV6_V6ONLY for server, %s", strerror(errno));
					close (sfd);
					continue;
				}
				struct sockaddr_in6 bip;
				bip.sin6_flowinfo = 0;
				bip.sin6_scope_id = 0;
				bip.sin6_family = AF_INET6;
				if (ba) bip.sin6_addr = in6addr_any;
				else if (!inet_pton(AF_INET6, bind_ip, &(bip.sin6_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin6_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					close (sfd);
					if (ba) {
						namespace = PF_INET;
						ip6 = 0;
						goto sock;
					}
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					continue;
				}
			} else {
				struct sockaddr_in bip;
				bip.sin_family = AF_INET;
				if (!inet_aton(bind_ip, &(bip.sin_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					close (sfd);
					continue;
				}
			}
		} else if (namespace == PF_LOCAL) {
			struct sockaddr_un uip;
			strncpy(uip.sun_path, bind_file, 108);
			if (bind(sfd, (struct sockaddr*) &uip, sizeof(uip))) {
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
				else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid family for server: %s", serv->id);
			else errlog(delog, "Invalid family for server\n");
			close (sfd);
			continue;
		}
		if (propo == SOCK_STREAM && listen(sfd, 50)) {
			if (serv->id != NULL) errlog(delog, "Error listening on socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error listening on socket for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (propo == SOCK_STREAM && fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (serv->id != NULL) errlog(delog, "Error setting non-blocking for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting non-blocking for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		struct logsess* slog = xmalloc(sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = getConfigValue(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
		const char* lel = getConfigValue(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
		const char* zone = getConfigValue(serv, "master-zone");
		int zfd = -1;
		int mysql = 0;
		char* mysql_host = NULL;
		int mysql_port = 0;
		char* mysql_user = NULL;
		char* mysql_pass = NULL;
		char* mysql_schema = NULL;
		int mysql_refresh = 60;
		if (streq_nocase(zone, "mysql")) {
#ifndef SUPPORTS_MYSQL
			if (serv->id != NULL) errlog(delog, "Invalid master-zone for server: %s (mysql not supported by build)", serv->id);
			else errlog(delog, "Invalid master-zone for server (mysql not supported by build)");
			close (sfd);
			continue;
#endif
			zone = NULL;
			mysql = 1;
			mysql_host = getConfigValue(serv, "mysql-host");
			if (mysql_host == NULL) {
				if (serv->id != NULL) errlog(delog, "Invalid mysql-host for server: %s, assuming localhost", serv->id);
				else errlog(delog, "Invalid mysql-host for server, assuming localhost\n");
				mysql_host = "localhost";
			}
			const char* mp = getConfigValue(serv, "mysql-port");
			if (mp == NULL) {
				if (serv->id != NULL) errlog(delog, "Invalid mysql-port for server: %s, assuming 3306", serv->id);
				else errlog(delog, "Invalid mysql-port for server, assuming 3306\n");
				mp = "3306";
			}
			mysql_port = atol(mp);
			mp = getConfigValue(serv, "mysql-refresh");
			if (mp == NULL) {
				if (serv->id != NULL) errlog(delog, "Invalid mysql-refresh for server: %s, assuming 60 seconds", serv->id);
				else errlog(delog, "Invalid mysql-refresh for server, assuming 60 seconds\n");
			} else mysql_refresh = atol(mp);
			mysql_user = getConfigValue(serv, "mysql-user");
			if (mysql_user == NULL) {
				if (serv->id != NULL) errlog(delog, "Invalid mysql-user for server: %s", serv->id);
				else errlog(delog, "Invalid mysql-user for server\n");
				close(sfd);
				continue;
			}
			mysql_pass = getConfigValue(serv, "mysql-pass");
			mysql_schema = getConfigValue(serv, "mysql-schema");
			if (mysql_schema == NULL) {
				if (serv->id != NULL) errlog(delog, "Invalid mysql-schema for server: %s, assuming dns", serv->id);
				else errlog(delog, "Invalid mysql-schema for server, assuming dns\n");
				mysql_schema = "dns";
			}
		} else if (zone == NULL || (zfd = open(zone, O_CREAT | O_RDONLY, 0664)) < 0) {
			if (serv->id != NULL) errlog(delog, "Invalid master-zone for server: %s", serv->id);
			else errlog(delog, "Invalid master-zone for server");
			close (sfd);
			continue;
		}
		if (zfd >= 0) close(zfd);
		struct zone* zonep = zone == NULL ? NULL : xmalloc(sizeof(struct zone));
		if (zone != NULL) {
			zonep->domain = "@";
			if (readZone(zonep, zone, "/etc/avuna/dns/", slog) < 0) {
				if (serv->id != NULL) errlog(delog, "Invalid master-zone for server: %s, %s", serv->id, strerror(errno));
				else errlog(delog, "Invalid master-zone for server: %s", strerror(errno));
				close (sfd);
				continue;
			}
		}
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
			struct udptcp_accept_param pt;
			pt.tcp = 1;
			pt.param.accept = ap;
			aps[i] = pt;
		} else {
			if (serv->id != NULL) acclog(slog, "Server %s listening!", serv->id);
			else acclog(slog, "Server listening!");
			struct udptcp_accept_param pt;
			pt.tcp = 0;
			struct udp_accept_param uap;
			uap.works = xmalloc(sizeof(struct udpwork_param*) * tc);
			uap.works_count = tc;
			uap.sfd = sfd;
			pt.param.udp = uap;
			aps[i] = pt;
		}
		struct mysql_data* mysql_data = xmalloc(sizeof(struct mysql_data));
		mysql_data->mysql = mysql;
		mysql_data->mysql_host = mysql_host;
		mysql_data->mysql_port = mysql_port;
		mysql_data->mysql_user = mysql_user;
		mysql_data->mysql_pass = mysql_pass;
		mysql_data->mysql_schema = mysql_schema;
		mysql_data->czone = NULL;
		mysql_data->mysql_refresh = mysql_refresh;
		mysql_data->complete = 0;
		mysql_data->szone = NULL;
		//thrs = new_collection(0);
#ifdef SUPPORTS_MYSQL
		if (mysql) {
			pthread_t ptx;
			int pc = pthread_create(&ptx, NULL, mysql_thread, mysql_data);
			if (pc) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, mysql will not update @ %s server.", pc, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, mysql will not update.", pc);
			}/* else {
			 struct thrmng* tm = xcalloc(sizeof(struct thrmng));
			 tm->pt = ptx;
			 tm->name = "Mysql Thread";
			 pthread_getcpuclockid(ptx, &tm->cid);
			 add_collection(thrs, tm);
			 }*/
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
				wp->mysql = mysql_data;
				aps[i].param.accept->works[x] = wp;
			} else {
				struct udpwork_param* uwp = xmalloc(sizeof(struct udpwork_param));
				uwp->logsess = slog;
				uwp->i = x;
				uwp->sfd = sfd;
				uwp->zone = zonep;
				uwp->mysql = mysql_data;
				aps[i].param.udp.works[x] = uwp;
			}
		}
		sr++;
	}
	const char* uids = getConfigValue(dm, "uid");
	const char* gids = getConfigValue(dm, "gid");
	uid_t uid = uids == NULL ? 0 : atol(uids);
	uid_t gid = gids == NULL ? 0 : atol(gids);
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
	for (int i = 0; i < servsl; i++) {
		pthread_t pt;
		for (int x = 0; x < (aps[i].tcp ? aps[i].param.accept->works_count : aps[i].param.udp.works_count); x++) {
			int c = aps[i].tcp ? pthread_create(&pt, NULL, (void *) run_work, aps[i].param.accept->works[x]) : pthread_create(&pt, NULL, (void *) run_udpwork, aps[i].param.udp.works[x]);
			if (c != 0) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging @ %s server.", c, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging.", c);
			}/* else {
			 struct thrmng* tm = xcalloc(sizeof(struct thrmng));
			 tm->pt = pt;
			 tm->name = xmalloc(129);
			 tm->name[128] = 0;
			 snprintf(tm->name, 128, "Worker Thread (%s) #%i", aps[i].tcp ? "TCP" : "UDP", i);
			 pthread_getcpuclockid(pt, &tm->cid);
			 add_collection(thrs, tm);
			 }*/
		}
		if (aps[i].tcp) {
			int c = pthread_create(&pt, NULL, (void *) run_accept, aps[i].param.accept);
			if (c != 0) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, server %s is shutting down.", c, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, server is shutting down.", c);
				close(aps[i].param.accept->server_fd);
			}/* else {
			 struct thrmng* tm = xcalloc(sizeof(struct thrmng));
			 tm->pt = pt;
			 tm->name = xmalloc(129);
			 tm->name[128] = 0;
			 snprintf(tm->name, 128, "Accept Thread #%i", i);
			 pthread_getcpuclockid(pt, &tm->cid);
			 add_collection(thrs, tm);
			 }*/
		}
	}
	while (sr > 0) {
		/*for (size_t i = 0; i < thrs->size; i++) {
		 if (thrs->data[i] != NULL) {
		 struct thrmng* tm = thrs->data[i];
		 struct timespec ts;
		 clock_gettime(tm->cid, &ts);
		 double tt = (double) ts.tv_sec + ((double) ts.tv_nsec / 1000000.);
		 printf("%s: %f s (+%f)\n", tm->name, tt, tt - tm->prevtime);
		 tm->prevtime = tt;
		 }
		 }*/
		sleep(60);
	}
	return 0;
}
