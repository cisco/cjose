/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SRC_HEADER_INT_H
#define SRC_HEADER_INT_H

#include <stddef.h>

#include "cjose/header.h"

bool _cjose_header_validate_crit(cjose_header_t *header, const char *const *supported, size_t supported_len, cjose_err *err);

// RFC 7516 section 7.2.1: the member names of the JWE protected header, the JWE
// shared unprotected header and a JWE per-recipient unprotected header must be
// disjoint. Entries may be NULL.
bool _cjose_header_validate_disjoint(cjose_header_t *const *headers, size_t headers_len, cjose_err *err);

#endif // SRC_HEADER_INT_H
