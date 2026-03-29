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
