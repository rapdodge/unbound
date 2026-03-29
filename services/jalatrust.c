/*
 * services/jalatrust.c - JALA Trust service implementation
 *
 * Copyright (c) 2025, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains the JALA Trust service implementation.
 * Uses for fast database lookups.
 */

#include "config.h"
#include "jalatrust.h"
#include "util/config_file.h"
#include "util/log.h"
#include "util/data/dname.h"
#include "sldns/rrdef.h"
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct jalatrust* jalatrust_create(const char* filename, struct config_file* cfg)
{
	struct jalatrust* jt;
	const char* open_path;

	/* Return NULL if disabled */
	if(!filename || strlen(filename) == 0)
		return NULL;

	/* After chroot, strip the chroot prefix from the path.
	 * e.g. if chroot="/etc/unbound" and filename="/etc/unbound/db/blacklist.db"
	 * then open_path="/db/blacklist.db" */
	open_path = filename;
	if(cfg->chrootdir && cfg->chrootdir[0] &&
		strncmp(filename, cfg->chrootdir, strlen(cfg->chrootdir)) == 0) {
		open_path = filename + strlen(cfg->chrootdir);
	}

	log_info("jalatrust: loading database from '%s' (open path: '%s')", 
		filename, open_path);

	jt = (struct jalatrust*)calloc(1, sizeof(*jt));
	if(!jt) return NULL;

	jt->filename = strdup(filename);
	if(!jt->filename) {
		free(jt);
		return NULL;
	}

	/* Open CDB file using chroot-adjusted path */
	jt->fd = open(open_path, O_RDONLY);
	if(jt->fd < 0) {
		log_err("jalatrust: cannot open database file '%s': %s",
			open_path, strerror(errno));
		free(jt->filename);
		free(jt);
		return NULL;
	}

	/* Initialize CDB */
	if(cdb_init(&jt->cdb, jt->fd) < 0) {
		log_err("jalatrust: cannot initialize database from '%s'", open_path);
		close(jt->fd);
		free(jt->filename);
		free(jt);
		return NULL;
	}

	lock_basic_init(&jt->lock);
	log_info("jalatrust: database loaded successfully from '%s'", open_path);

	return jt;
}

void jalatrust_delete(struct jalatrust* jt)
{
	if(!jt) return;

	lock_basic_destroy(&jt->lock);
	cdb_free(&jt->cdb);
	if(jt->fd >= 0)
		close(jt->fd);
	free(jt->filename);
	free(jt);
}

int jalatrust_lookup(struct jalatrust* jt, uint8_t* qname, size_t qname_len)
{
	int result;
	char qname_str[LDNS_MAX_DOMAINLEN];
	uint8_t qname_lower[LDNS_MAX_DOMAINLEN];
	uint8_t* lookup_name;
	size_t lookup_len;

	if(!jt || !qname)
		return 0;

	/* Make a lowercase copy for lookup (database stores lowercase) */
	if(qname_len > sizeof(qname_lower))
		return 0;
	memcpy(qname_lower, qname, qname_len);
	query_dname_tolower(qname_lower);

	/* Debug: show what we're looking up */
	dname_str(qname_lower, qname_str);
	verbose(VERB_ALGO, "jalatrust: looking up domain: %s (wire len=%zu)", qname_str, qname_len);

	/* Check if the query name looks like a bare IP address.
	 * e.g. "111.90.150.182." - this is a single label followed by root,
	 * but actually we need to check the text form. */
	{
		char ip_check[LDNS_MAX_DOMAINLEN];
		size_t ip_len;
		struct in_addr addr4;
		struct in6_addr addr6;

		dname_str(qname_lower, ip_check);
		/* dname_str produces "label.label." with trailing dot, remove it */
		ip_len = strlen(ip_check);
		if(ip_len > 0 && ip_check[ip_len-1] == '.')
			ip_check[ip_len-1] = '\0';

		/* Try parsing as IPv4 or IPv6 */
		if(inet_pton(AF_INET, ip_check, &addr4) == 1 ||
		   inet_pton(AF_INET6, ip_check, &addr6) == 1) {
			/* This query name IS an IP address.
			 * Look it up directly in the CDB as a text key. */
			size_t key_len = strlen(ip_check);
			verbose(VERB_ALGO, "jalatrust: query name is IP address: %s", ip_check);

			lock_basic_lock(&jt->lock);
			result = cdb_find(&jt->cdb, ip_check, (unsigned int)key_len);
			lock_basic_unlock(&jt->lock);

			if(result == 1) {
				verbose(VERB_QUERY, "jalatrust: IP address blocked: %s",
					ip_check);
			}
			if(result != 0)
				return result;
			/* If not found as IP, fall through to domain lookup */
		}
	}

	lock_basic_lock(&jt->lock);

	/* Try exact match first, then walk up parent domains.
	 * e.g. for www.xnxx.com: try www.xnxx.com, then xnxx.com, then com.
	 * Stop before root label "." (len==1) since we never block root. */
	lookup_name = qname_lower;
	lookup_len = qname_len;
	result = 0;

	while(lookup_len > 1) {
		result = cdb_find(&jt->cdb, lookup_name, lookup_len);
		if(result != 0) {
			/* Found (1) or error (-1), stop walking */
			break;
		}
		/* Not found, try parent domain by stripping leftmost label */
		dname_remove_label(&lookup_name, &lookup_len);
	}

	lock_basic_unlock(&jt->lock);

	if(result == 1) {
		char match_str[LDNS_MAX_DOMAINLEN];
		dname_str(lookup_name, match_str);
		verbose(VERB_QUERY, "jalatrust: domain blocked: %s (matched: %s)",
			qname_str, match_str);
	}

	return result;
}

int jalatrust_lookup_ip(struct jalatrust* jt, struct sockaddr_storage* addr,
	socklen_t addrlen)
{
	char ip_str[INET6_ADDRSTRLEN];
	uint8_t wire[LDNS_MAX_DOMAINLEN];
	size_t wire_len;
	int result;

	if(!jt || !addr)
		return 0;

	(void)addrlen; /* used for type-safety, not needed for conversion */

	/* Convert binary IP to text string */
	if(addr->ss_family == AF_INET) {
		struct sockaddr_in* sa4 = (struct sockaddr_in*)addr;
		if(!inet_ntop(AF_INET, &sa4->sin_addr, ip_str, sizeof(ip_str)))
			return 0;
	} else if(addr->ss_family == AF_INET6) {
		struct sockaddr_in6* sa6 = (struct sockaddr_in6*)addr;
		if(!inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, sizeof(ip_str)))
			return 0;
	} else {
		return 0; /* unknown address family */
	}

	verbose(VERB_ALGO, "jalatrust: checking response IP: %s", ip_str);

	/* Convert IP text to wire format (DNS labels).
	 * e.g. "66.254.114.41" -> \x02 66 \x03 254 \x03 114 \x02 41 \x00
	 * IPs are stored in wire format in the CDB, same as domains. */
	{
		const char* p = ip_str;
		wire_len = 0;
		while(*p) {
			const char* dot = strchr(p, '.');
			size_t tlen = dot ? (size_t)(dot - p) : strlen(p);
			if(tlen == 0 || tlen > 63 ||
				wire_len + 1 + tlen >= sizeof(wire))
				return 0;
			wire[wire_len++] = (uint8_t)tlen;
			memcpy(wire + wire_len, p, tlen);
			wire_len += tlen;
			p += tlen;
			if(*p == '.') p++;
		}
		wire[wire_len++] = 0; /* root label */
	}

	lock_basic_lock(&jt->lock);
	result = cdb_find(&jt->cdb, wire, (unsigned int)wire_len);
	lock_basic_unlock(&jt->lock);

	if(result == 1) {
		verbose(VERB_QUERY, "jalatrust: response IP blocked: %s", ip_str);
	}

	return result;
}
