 /*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "include/util_int.h"

#include <cjose/util.h>

#include <jansson.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

static cjose_alloc_fn_t _alloc;
static cjose_realloc_fn_t _realloc;
static cjose_dealloc_fn_t _dealloc;

void cjose_set_alloc_funcs(cjose_alloc_fn_t alloc,
                           cjose_alloc3_fn_t alloc3,
                           cjose_realloc_fn_t realloc,
                           cjose_realloc3_fn_t realloc3,
                           cjose_dealloc_fn_t dealloc,
                           cjose_dealloc3_fn_t dealloc3)
{
    // save "locally"
    _alloc = alloc;
    _realloc = realloc;
    _dealloc = dealloc;
    // set upstream
    json_set_alloc_funcs(_alloc, _dealloc);
#if (CJOSE_OPENSSL_11X)
    CRYPTO_set_mem_functions(alloc3, realloc3, dealloc3);
#else
    CRYPTO_set_mem_functions(alloc, realloc, dealloc);
#endif
}

cjose_alloc_fn_t cjose_get_alloc()
{
    return (!_alloc) ?
           malloc :
           _alloc;
}

cjose_realloc_fn_t cjose_get_realloc()
{
    return (!_realloc) ?
           realloc :
           _realloc;
}

cjose_dealloc_fn_t cjose_get_dealloc()
{
    return (!_dealloc) ?
           free :
           _dealloc;
}

int cjose_const_memcmp(
        const uint8_t *a,
        const uint8_t *b,
        const size_t size)
{
    unsigned char result = 0;
    for (size_t i = 0; i < size; i++)
    {
        result |= a[i] ^ b[i];
    }

    return result;
}

char *_cjose_strndup(const char *str, ssize_t len, cjose_err *err)
{
    if (NULL == str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    if (0 > len)
    {
        len = strlen(str);
    }

    char *result = cjose_get_alloc()(sizeof(char) * (len + 1));
    if (!result)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memcpy(result, str, len);
    result[len] = 0;

    return result;
}

json_t *_cjose_json_stringn(const char *value, size_t len, cjose_err *err) {
	json_t *result = NULL;
#if JANSSON_VERSION_HEX <= 0x020600
    char *s = _cjose_strndup(value, len, err);
    if (!s)
    {
    	return NULL;
    }
    result = json_string(s);
    if (!result)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    cjose_get_dealloc()(s);
#else
    result = json_stringn(value, len);
    if (!result)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
#endif
    return result;
}
