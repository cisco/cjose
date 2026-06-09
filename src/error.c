/**
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <openssl/err.h>
#include "cjose/error.h"

////////////////////////////////////////////////////////////////////////////////
static const char *_ERR_MSG_TABLE[] = { "no error", "invalid argument", "invalid state", "out of memory", "crypto error" };

////////////////////////////////////////////////////////////////////////////////
const char *cjose_err_message(cjose_errcode code)
{
    const char *retval = NULL;
    if (CJOSE_ERR_CRYPTO == code)
    {
        // for crypto errors, return the most recent openssl error as message;
        // render it into a thread-local buffer since ERR_error_string with a
        // NULL buffer returns a static buffer shared across threads
        static __thread char buf[256];
        unsigned long err = ERR_get_error();
        while (0 != err)
        {
            ERR_error_string_n(err, buf, sizeof(buf));
            retval = buf;
            err = ERR_get_error();
        }
    }
    if (NULL == retval)
    {
        // the code is caller-supplied; don't index the table out of bounds
        if ((size_t)code >= sizeof(_ERR_MSG_TABLE) / sizeof(_ERR_MSG_TABLE[0]))
        {
            return "unknown error";
        }
        retval = _ERR_MSG_TABLE[code];
    }
    return retval;
}
