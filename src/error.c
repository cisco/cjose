/**
 *
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <openssl/err.h>
#include "cjose/error.h"

// thread-local storage specifier: MSVC spells it __declspec(thread),
// GCC/Clang use __thread, C11 has _Thread_local
#if defined(_MSC_VER)
#define CJOSE_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define CJOSE_THREAD_LOCAL __thread
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define CJOSE_THREAD_LOCAL _Thread_local
#else
#define CJOSE_THREAD_LOCAL
#endif

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
        static CJOSE_THREAD_LOCAL char buf[256];
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
