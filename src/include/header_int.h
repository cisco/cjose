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

// RFC 7515 section 4.1.11 and RFC 7516 section 4.1.13: a "crit" list names
// extensions that have to be understood and processed. cjose implements none,
// and a producer may not list a name the specifications define, so a header
// that carries the list is refused. Entries may be NULL.
bool _cjose_header_validate_crit(cjose_header_t *const *headers, size_t headers_len, cjose_err *err);

// RFC 7516 section 7.2.1: the member names of the JWE protected header, the JWE
// shared unprotected header and a JWE per-recipient unprotected header must be
// disjoint. Entries may be NULL.
bool _cjose_header_validate_disjoint(cjose_header_t *const *headers, size_t headers_len, cjose_err *err);

#endif // SRC_HEADER_INT_H
