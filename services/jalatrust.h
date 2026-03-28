/*
 * services/jalatrust.h - JALA Trust service for CDB-based domain blacklisting
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
 * This file contains functions to enable JALA Trust service.
 */

#ifndef SERVICES_JALATRUST_H
#define SERVICES_JALATRUST_H

#include <cdb.h>
#include "util/locks.h"

/* Forward declaration */
struct config_file;

/**
 * JALATRUST structure for database-based domain blacklisting
 */
struct jalatrust {
	int fd;			/** database file descriptor */
	struct cdb cdb;		/** database structure */
	char* filename;		/** database file path */
	lock_basic_type lock;	/** Thread safety lock */
};

/**
 * Initialize JALATRUST from config file path
 * @param filename: path to database file (NULL or empty string disables)
 * @param cfg: config file for path adjustment
 * @return: initialized jalatrust struct, NULL if disabled or on error
 */
struct jalatrust* jalatrust_create(const char* filename, struct config_file* cfg);

/**
 * Cleanup JALATRUST resources
 * @param jt: jalatrust struct to delete
 */
void jalatrust_delete(struct jalatrust* jt);

/**
 * Check if domain is blacklisted
 * @param jt: jalatrust struct
 * @param qname: query name (wire format)
 * @param qname_len: length of qname
 * @return: 1 if found (blacklisted), 0 if not found, -1 on error
 */
int jalatrust_lookup(struct jalatrust* jt, uint8_t* qname, size_t qname_len);

/**
 * Check if jalatrust is enabled
 * @param jt: jalatrust struct
 * @return: true if enabled
 */
#define jalatrust_enabled(jt) ((jt) != NULL && (jt)->filename != NULL)

#endif /* SERVICES_JALATRUST_H */
