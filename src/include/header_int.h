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

// RFC 7515 section 4.1.11 and RFC 7516 section 4.1.13: validate the "crit" list
// of a JOSE header. headers[0] is the protected header, which is the only one
// that may carry the list, and headers[] together make up the JOSE header the
// listed names have to occur in; entries other than the first may be NULL.
bool _cjose_header_validate_crit(
    cjose_header_t *const *headers, size_t headers_len, const char *const *supported, size_t supported_len, cjose_err *err);

// RFC 7515 section 4.1.11: every name in the "crit" list of headers[0] must
// occur as a header parameter name within the JOSE header. Only for a header
// that is complete: when producing, the algorithm still adds parameters of its
// own after the rest of the list has been validated.
bool _cjose_header_validate_crit_present(cjose_header_t *const *headers, size_t headers_len, cjose_err *err);

// RFC 7516 section 7.2.1: the member names of the JWE protected header, the JWE
// shared unprotected header and a JWE per-recipient unprotected header must be
// disjoint. Entries may be NULL.
bool _cjose_header_validate_disjoint(cjose_header_t *const *headers, size_t headers_len, cjose_err *err);

#endif // SRC_HEADER_INT_H
