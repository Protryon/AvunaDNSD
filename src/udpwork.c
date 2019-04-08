/*
 * udpwork.c
 *
 *  Created on: Jan 30, 2016
 *      Author: root
 */

#include "udpwork.h"
#include "util.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include "zone.h"
#include "xstring.h"
#include <errno.h>
#include "accept.h"
#include <arpa/inet.h>
#include "version.h"

struct dnsheader {
		uint16_t id;
		uint8_t rd :1;
		uint8_t tc :1;
		uint8_t aa :1;
		uint8_t opcode :4;
		uint8_t QR :1;
		uint8_t rcode :4;
		uint8_t z :3;
		uint8_t ra :1;
		uint16_t qdcount;
		uint16_t ancount;
		uint16_t nscount;
		uint16_t arcount;
};

struct dnsquestion {
		char* domain;
		uint16_t type;
		;uint16_t class;
		int logged;
		int dcab;
};

struct dnsrecord {
		char* domain;
		uint16_t type;
		;uint16_t class;
		int32_t ttl;
		uint16_t rdlength;
		unsigned char* rd;
		struct dnsquestion* from;
		char* pdata;
		char* ad;
		char* pd1;
		char* pd2;
		int cax;
};

char* readDomain(unsigned char* data, size_t* doff, size_t len) {
	unsigned char x = 0;
	size_t i = *doff;
	char* dom = xmalloc(1);
	dom[0] = 0;
	int di = 0;
	int f = 0;
	while (i < len && (x = data[i]) > 0) {
		i++;
		if (!f) *doff = i;
		if ((x & 0xC0) == 0xC0) { // compressed
			uint16_t pt = 0;
			pt = (i & 0x3F) << 8;
			if (i + 1 < len) pt |= data[i + 1];
			i = pt;
			f = 1;
		} else if ((x & 0x80) == 0x80 || (x & 0x40) == 0x40) {
			xfree(dom);
			return NULL;
		}
		if (i >= len || i < 0) break;
		dom = xrealloc(dom, x + di + 2);
		memcpy(dom + di, data + i, x);
		dom[di + x] = '.';
		dom[di + x + 1] = 0;
		di += x + 1;
		i += x;
		if (!f) *doff = i;
	}
	if (!f) (*doff)++; // account for ending
	dom[di - 1] = 0;
	return dom;
}

char* dver = NULL;

void parseZone(struct dnsquestion* dq, uint16_t type, char* domain, struct zone* zone, struct dnsrecord*** rrecs, size_t* rrecsl, struct dnsrecord*** arrecs, size_t* arrecsl) {
	int rs = -1;
	struct zoneentry** zee = NULL;
	size_t zeel = 0;
	if (streq_nocase(domain, "version.bind") && type == 16) {
		*rrecs = xmalloc(sizeof(struct dnsrecord*));
		*rrecsl = 1;
		if (dver == NULL) {
			dver = xmalloc(2 + strlen("AvunaDNSD-" VERSION));
			dver[0] = 15;
			memcpy(dver + 1, "AvunaDNSD-" VERSION, strlen("AvunaDNSD-" VERSION));;
		}
		struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
		dr->class = 1;
		dr->domain = domain;
		dr->from = dq;
		dr->ad = NULL;
		dr->rd = (unsigned char*) dver;
		dr->rdlength = strlen(dver);
		dr->ttl = 3600;
		dr->type = 16;
		dr->pdata = ("AvunaDNSD-" VERSION);
		dr->cax = 1;
		(*rrecs)[0] = dr;
		return;
	}
	for (size_t i = 0; i < zone->entry_count; i++) {
		struct zoneentry* ze = zone->entries[i];
		if (ze->type == 0 && domeq(ze->part.subzone->domain, domain, (*rrecsl) == 0) && rs < 0) {
			parseZone(dq, type, domain, ze->part.subzone, rrecs, rrecsl, arrecs, arrecsl);
		} else if (ze->type == 1 && (ze->part.dom.type == type || ze->part.dom.pt)) {
			int ext = dq->dcab != ze->part.dom.type;
			if (ext) if (startsWith(ze->part.dom.domain, "~")) {
				for (size_t x = 0; x < *rrecsl; x++) {
					struct dnsrecord* dr = (*rrecs)[x];
					if (dr->type == type) {
						ext = 0;
						break;
					}
				}
			}
			if (domeq(ze->part.dom.domain, domain, ext)) {
				if (ze->part.dom.data_len == 0 && (ze->part.dom.ad == NULL || strlen(ze->part.dom.ad) < 1)) {
					dq->dcab = ze->part.dom.type;
					continue;
				}
				if (rs >= 0) {
					if (zee == NULL) {
						zee = xmalloc(sizeof(struct zoneentry*));
						zeel = 0;
					} else {
						zee = xrealloc(zee, sizeof(struct zoneentry*) * (zeel + 1));
					}
					zee[zeel++] = ze;
				} else {
					if (*rrecs == NULL) {
						*rrecs = xmalloc(sizeof(struct dnsrecord*));
						(*rrecsl) = 0;
					} else {
						*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
					}
					struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
					dr->from = dq;
					dr->pdata = ze->part.dom.pdata;
					dr->domain = domain;
					dr->type = ze->part.dom.type;
					dr->class = 1;
					dr->ttl = ze->part.dom.ttlmin + (ze->part.dom.ttlmax == ze->part.dom.ttlmin ? 0 : (rand() % (ze->part.dom.ttlmax - ze->part.dom.ttlmin)));
					dr->rdlength = ze->part.dom.data_len;
					dr->rd = ze->part.dom.data;
					dr->ad = ze->part.dom.ad;
					dr->pd1 = ze->part.dom.pd1;
					dr->pd2 = ze->part.dom.pd2;
					dr->cax = 0;
					(*rrecs)[(*rrecsl)++] = dr;
				}
			}
		} else if (ze->type == 2) {
			rs = ze->part.rrst.per;
		} else if (ze->type == 3) {
			if (rs > 0) {
				if (zeel <= rs) {
					for (size_t j = 0; j < zeel; j++) { // TODO: fix code repititon
						struct zoneentry* ze = zee[j];
						if (*rrecs == NULL) {
							*rrecs = xmalloc(sizeof(struct dnsrecord*));
							(*rrecsl) = 0;
						} else {
							*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
						}
						struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
						dr->from = dq;
						dr->pdata = ze->part.dom.pdata;
						dr->domain = domain;
						dr->type = ze->part.dom.type;
						dr->class = 1;
						dr->ttl = ze->part.dom.ttlmin + (ze->part.dom.ttlmax == ze->part.dom.ttlmin ? 0 : (rand() % (ze->part.dom.ttlmax - ze->part.dom.ttlmin)));
						dr->rdlength = ze->part.dom.data_len;
						dr->rd = ze->part.dom.data;
						dr->ad = ze->part.dom.ad;
						dr->pd1 = ze->part.dom.pd1;
						dr->pd2 = ze->part.dom.pd2;
						dr->cax = 0;
						(*rrecs)[(*rrecsl)++] = dr;
					}
				} else {
					for (size_t j = 0; j < rs; j++) {
						size_t x = rand() % zeel;
						int f = 0;
						for (size_t y = 0; y < zeel; y++) {
							struct zoneentry* zed = zee[x];
							if (zed == NULL) continue;
							zee[x] = NULL;
							if (*rrecs == NULL) {
								*rrecs = xmalloc(sizeof(struct dnsrecord*));
								(*rrecsl) = 0;
							} else {
								*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
							}
							struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
							dr->from = dq;
							dr->pdata = zed->part.dom.pdata;
							dr->domain = domain;
							dr->type = zed->part.dom.type;
							dr->class = 1;
							dr->ttl = zed->part.dom.ttlmin + (zed->part.dom.ttlmax == zed->part.dom.ttlmin ? 0 : (rand() % (zed->part.dom.ttlmax - zed->part.dom.ttlmin)));
							dr->rdlength = zed->part.dom.data_len;
							dr->rd = zed->part.dom.data;
							dr->ad = zed->part.dom.ad;
							dr->pd1 = zed->part.dom.pd1;
							dr->pd2 = zed->part.dom.pd2;
							dr->cax = 0;
							(*rrecs)[(*rrecsl)++] = dr;
							x++;
							if (x == zeel) x = 0;
							f = 1;
							break;
						}
						if (!f) {
							for (size_t j = 0; j < zeel; j++) {
								struct zoneentry* ze = zee[j];
								if (ze == NULL) break;
								if (*rrecs == NULL) {
									*rrecs = xmalloc(sizeof(struct dnsrecord*));
									(*rrecsl) = 0;
								} else {
									*rrecs = xrealloc(*rrecs, sizeof(struct dnsrecord*) * ((*rrecsl) + 1));
								}
								struct dnsrecord* dr = xmalloc(sizeof(struct dnsrecord));
								dr->from = dq;
								dr->pdata = ze->part.dom.pdata;
								dr->domain = domain;
								dr->type = ze->part.dom.type;
								dr->class = 1;
								dr->ttl = ze->part.dom.ttlmin + (ze->part.dom.ttlmax == ze->part.dom.ttlmin ? 0 : (rand() % (ze->part.dom.ttlmax - ze->part.dom.ttlmin)));
								dr->rdlength = ze->part.dom.data_len;
								dr->rd = ze->part.dom.data;
								dr->ad = ze->part.dom.ad;
								dr->pd1 = ze->part.dom.pd1;
								dr->pd2 = ze->part.dom.pd2;
								dr->cax = 0;
								(*rrecs)[(*rrecsl)++] = dr;
								break;
							}
						}
					}
				}
			}
			if (zee != NULL) xfree(zee);
			zee = NULL;
			zeel = 0;
			rs = -1;
		}
	}
	if (*rrecsl == 0) {
		if (type == 1) {
			parseZone(dq, 5, domain, zone, rrecs, rrecsl, arrecs, arrecsl);
		}
	}
	if (arrecs != rrecs) {
		if (type == 5) {
			size_t tr = *rrecsl;
			for (size_t i = 0; i < tr; i++) {
				if (!(*rrecs)[i]->cax && (*rrecs)[i]->type == 5) {
					(*rrecs)[i]->cax = 1;
					parseZone(dq, 1, (*rrecs)[i]->pdata, zone, arrecs, arrecsl, arrecs, arrecsl);
				}
			}
		} else if (type == 15) {
			size_t tr = *rrecsl;
			for (size_t i = 0; i < tr; i++) {
				if (!(*rrecs)[i]->cax && (*rrecs)[i]->type == 15) {
					(*rrecs)[i]->cax = 1;
					char* dom = (*rrecs)[i]->pdata;
					dom = strchr(dom, ' ');
					if (dom != NULL && strlen(dom) > 2) {
						parseZone(dq, 1, dom + 1, zone, arrecs, arrecsl, arrecs, arrecsl);
					}
				}
			}
		}
	}
}

void writeDomain(int compress, char* dom, unsigned char* buf, size_t dlx, size_t ml, size_t* cs) {
	size_t sd = strlen(dom); // TODO: partial domain compression ie ruby.example.com compress to ruby.blah.
	if (sd + 2 + *cs > ml) {
		return;
	}
	if (compress) {
		size_t dl = strlen(dom) + 1;
		size_t mlx = 0;
		size_t mi = 0;
		for (size_t x = 1; x < (dlx < 16384 ? dlx : 16384); x++) {
			if (buf[x] == dom[mlx] || dom[mlx] == '.') {
				if (mi == 0) mi = x;
				mlx++;
				if (mlx == dl) {
					break;
				}
			} else {
				mlx = 0;
				mi = 0;
			}
		}
		if (mlx != dl) mi = 0;
		if (mi > 0) {
			mi--;
			buf[*cs] = 0xC0 | ((mi & 0x3F00) >> 8);
			(*cs)++;
			buf[*cs] = mi & 0xFF;
			(*cs)++;
			return;
		}
	}
	unsigned char* lb = buf + *cs;
	*lb = 0;
	(*cs)++;
	for (size_t i = 0; i < sd; i++) {
		if (dom[i] == '.') {
			//dom should be something like .com\0 or .example.com\0
			if (compress) {
				size_t dl = strlen(dom + i);
				size_t mlx = 0;
				size_t mi = 0;
				for (size_t x = 1; x < (dlx < 16384 ? dlx : 16384); x++) {
					if (buf[x] == dom[mlx + i] || dom[mlx + i] == '.') {
						if (mi == 0) mi = x;
						mlx++;
						if (mlx == dl) {
							break;
						}
					} else {
						mlx = 0;
						mi = 0;
					}
				}
				if (mlx != dl) mi = 0;
				if (mi > 0) {
					buf[*cs] = 0xC0 | ((mi & 0x3F00) >> 8);
					(*cs)++;
					buf[*cs] = mi & 0xFF;
					(*cs)++;
					return;
				}
			}
			lb = buf + *cs;
			*lb = 0;
		} else {
			(*lb)++;
			if (*lb >= 63) {
				lb = buf + *cs;
				*lb = 0;
			} else buf[*cs] = dom[i];
		}
		(*cs)++;
	}
	buf[(*cs)++] = 0;
}

void handleUDP(struct mysql_data* mysql, struct logsess* log, struct zone* zone, int sfd, void* buf, size_t len, struct sockaddr* addr, socklen_t addrl, struct conn* conn) {
	if (mysql != NULL && mysql->szone != NULL) zone = mysql->szone;
	if (zone == NULL) return;
	if (len < 12) return;
	struct dnsheader* head = buf;
	if (head->QR == 1) return;
	if (head->qdcount == 0) return;
	if (htons(head->qdcount) * 5 > len - 12) return;
	head->qdcount = (head->qdcount >> 8) | ((head->qdcount & 0xff) << 8);
	head->ancount = (head->ancount >> 8) | ((head->ancount & 0xff) << 8);
	head->nscount = (head->nscount >> 8) | ((head->nscount & 0xff) << 8);
	head->arcount = (head->arcount >> 8) | ((head->arcount & 0xff) << 8);
//unsigned char* qrs = buf + 12;
	struct dnsquestion qds[head->qdcount];
	size_t cp = 12;
	for (int i = 0; i < head->qdcount; i++) {
		qds[i].domain = readDomain(buf, &cp, len);
		if (!qds[i].domain) return;
		qds[i].logged = 0;
		uint16_t* tt = buf + cp;
		qds[i].type = htons(*tt);
		cp += 2;
		tt = buf + cp;
		qds[i].class = htons(*tt);
		cp += 2;
		if (qds[i].class != 1) return; //TODO: perhaps return an error?
	}
//as a authoritative server only, we only need to see up to questions.
	struct dnsheader* rhead = xmalloc(sizeof(struct dnsheader));
	rhead->id = head->id;
	rhead->rd = 0;
	rhead->tc = 0;
	rhead->aa = 1;
	rhead->opcode = 0;
	rhead->QR = 1;
	rhead->rcode = 0;
	rhead->z = 0;
	rhead->ra = 0;
	rhead->qdcount = head->qdcount;
	rhead->ancount = 0;
	rhead->nscount = 0;
	rhead->arcount = 0;
	struct dnsrecord** rrecs = NULL;
	size_t rrecsl = 0;
	struct dnsrecord** arrecs = NULL;
	size_t arrecsl = 0;
	if (head->opcode != 0) {
		rhead->rcode = 4;
		goto wr;
	}
	for (int x = 0; x < head->qdcount; x++) {
		qds[x].dcab = -1;
		parseZone(&qds[x], qds[x].type, qds[x].domain, zone, &rrecs, &rrecsl, &arrecs, &arrecsl);
	}
	rhead->ancount = rrecsl;
	rhead->arcount = arrecsl;
	wr: ;
	rhead->qdcount = htons(rhead->qdcount);
	rhead->ancount = htons(rhead->ancount);
	rhead->nscount = htons(rhead->nscount);
	rhead->arcount = htons(rhead->arcount);
	unsigned char* resp = (unsigned char*) rhead;
	size_t cs = 12;
	for (int i = 0; i < head->qdcount; i++) {
		struct dnsquestion* dq = &(qds[i]);
		size_t al = strlen(dq->domain) + 2 + 4;
		resp = xrealloc(resp, cs + al);
		writeDomain(1, dq->domain, resp, cs, cs + al, &cs);
		uint16_t tt = htons(dq->type);
		memcpy(resp + cs, &tt, 2);
		cs += 2;
		tt = htons(dq->class);
		memcpy(resp + cs, &tt, 2);
		cs += 2;
	}
	for (int i = 0; i < rrecsl + arrecsl; i++) {
		struct dnsrecord* dr = i < rrecsl ? rrecs[i] : arrecs[i - rrecsl];
		size_t al = strlen(dr->domain) + 2 + 10 + dr->rdlength;
		size_t pal = dr->ad == NULL ? 0 : strlen(dr->ad) + 2;
		if (dr->type == 6) pal += strlen(dr->pd1) + strlen(dr->pd2) + 4;
		resp = xrealloc(resp, cs + al + pal);
		size_t pcs = cs;
		writeDomain(1, dr->domain, resp, pcs, pcs + al + pal, &cs);
		uint16_t t = htons(dr->type);
		memcpy(resp + cs, &t, 2);
		cs += 2;
		t = htons(dr->class);
		memcpy(resp + cs, &t, 2);
		cs += 2;
		int32_t ttl = htonl(dr->ttl);
		memcpy(resp + cs, &ttl, 4);
		cs += 4;
		size_t pcx = cs;
		cs += 2;
		size_t ocs2 = cs;
		if (dr->type == 6) {
			writeDomain(1, dr->pd1, resp, pcx, pcx + al + pal, &cs);
			writeDomain(1, dr->pd2, resp, pcx, pcx + al + pal, &cs);
		}
		size_t dcs = cs - ocs2;
		cs += dr->rdlength;
		size_t ocs = cs;
		if (dr->ad != NULL) {
			writeDomain(1, dr->ad, resp, pcx, pcx + al + pal, &cs);
		}
		t = htons(dr->rdlength + (cs - ocs) + dcs);
		memcpy(resp + pcx, &t, 2);
		pcx += 2;
		memcpy(resp + pcx + dcs, dr->rd, dr->rdlength);
	}
	if (addr != NULL && cs > 512) {
		rhead = (struct dnsheader*) resp;
		cs = 512;
		rhead->tc = 1;
	}
	if (addr == NULL) { //tcp
		if (conn->writeBuffer != NULL) xfree(conn->writeBuffer);
		resp = xrealloc(resp, cs + 2);
		memmove(resp + 2, resp, cs);
		uint16_t cs16 = cs;
		cs16 = htons(cs16);
		memcpy(resp, &cs16, 2);
		conn->writeBuffer = resp;
		conn->writeBuffer_size = cs + 2;
	} else {
		sendto(sfd, resp, cs, 0, addr, addrl); //  sendto can fail, but what we do regardless is cleanup.
		xfree(resp);
	}
	char tip[48];
	const char* mip = tip;
	struct sockaddr* sa = conn == NULL ? addr : (struct sockaddr*) &conn->addr;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sip4 = (struct sockaddr_in*) sa;
		inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) sa;
		if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
			inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
		} else inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
	} else if (sa->sa_family == AF_LOCAL) {
		mip = "UNIX";
	} else {
		mip = "UNKNOWN";
	}
	for (int i = 0; i < rrecsl; i++) {
		struct dnsrecord* dr = rrecs[i];
		acclog(log, "%s requested %s for %s, returned %s %s", mip, typeString(dr->from->type), dr->from->domain, typeString(dr->type), dr->pdata);
		dr->from->logged = 1;
		xfree(dr);
	}
	for (int i = 0; i < arrecsl; i++) {
		struct dnsrecord* dr = arrecs[i];
		acclog(log, "%s requested %s for %s, returned<assume> %s %s", mip, typeString(dr->from->type), dr->from->domain, typeString(dr->type), dr->pdata);
		dr->from->logged = 1;
		xfree(dr);
	}
	if (rrecs != NULL) xfree(rrecs);
	if (rrecs != NULL) xfree(arrecs);
	for (int x = 0; x < head->qdcount; x++) {
		if (!qds[x].logged) {
			acclog(log, "%s requested %s for %s, returned nothing", mip, typeString(qds[x].type), qds[x].domain);
		}
		xfree(qds[x].domain);
	}
}

void run_udpwork(struct udpwork_param* param) {
	unsigned char* mbuf = xmalloc(512); // udp has a maximum of 512
	struct sockaddr_in6 addr;
	socklen_t addrl = sizeof(struct sockaddr_in6);
	while (1) {
		int x = recvfrom(param->sfd, mbuf, 512, 0, (struct sockaddr*) &addr, &addrl);
		if (param->mysql->mysql && param->mysql->complete && param->zone != param->mysql->czone) {
			if (param->zone != NULL) {
				freeZone(param->zone);
			}
			param->zone = param->mysql->czone;
		}
		if (x < 0) continue; // this shouldnt happen
		if (x > 0) {
			handleUDP(param->mysql, param->logsess, param->zone, param->sfd, mbuf, x, (struct sockaddr*) &addr, addrl, NULL);
		}
	}
	xfree(mbuf);
}
