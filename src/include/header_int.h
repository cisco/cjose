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

#endif // SRC_HEADER_INT_H
