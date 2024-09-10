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
static cjose_alloc3_fn_t _alloc3;
static cjose_realloc3_fn_t _realloc3;
static cjose_dealloc3_fn_t _dealloc3;

void *cjose_alloc_wrapped(size_t n) { return cjose_get_alloc3(void)(n, __FILE__, __LINE__); }
void *cjose_realloc_wrapped(void *p, size_t n) { return cjose_get_realloc3(void)(p, n, __FILE__, __LINE__); }
void cjose_dealloc_wrapped(void *p) { cjose_get_dealloc3(void)(p, __FILE__, __LINE__); }

void *cjose_alloc3_default(size_t n, const char *file, int line)
{
    CJOSE_UNUSED_PARAM(file);
    CJOSE_UNUSED_PARAM(line);
    return cjose_get_alloc(void)(n);
}

void *cjose_realloc3_default(void *p, size_t n, const char *file, int line)
{
    CJOSE_UNUSED_PARAM(file);
    CJOSE_UNUSED_PARAM(line);
    return cjose_get_realloc(void)(p, n);
}

void cjose_dealloc3_default(void *p, const char *file, int line)
{
    CJOSE_UNUSED_PARAM(file);
    CJOSE_UNUSED_PARAM(line);
    cjose_get_dealloc(void)(p);
}

static void cjose_apply_allocs(void)
{
    // set upstream
    json_set_alloc_funcs(cjose_get_alloc(void), cjose_get_dealloc(void));
#if defined(CJOSE_OPENSSL_11X)
    CRYPTO_set_mem_functions(cjose_get_alloc3(void), cjose_get_realloc3(void), cjose_get_dealloc3(void));
#else
    CRYPTO_set_mem_functions(cjose_get_alloc(void), cjose_get_realloc(void), cjose_get_dealloc(void));
#endif
}

void cjose_set_alloc_funcs(cjose_alloc_fn_t alloc, cjose_realloc_fn_t realloc, cjose_dealloc_fn_t dealloc)
{
    // save "locally"
    _alloc = alloc;
    _realloc = realloc;
    _dealloc = dealloc;
    _alloc3 = cjose_alloc3_default;
    _realloc3 = cjose_realloc3_default;
    _dealloc3 = cjose_dealloc3_default;

    cjose_apply_allocs(void);
}

void cjose_set_alloc_ex_funcs(cjose_alloc3_fn_t alloc3, cjose_realloc3_fn_t realloc3, cjose_dealloc3_fn_t dealloc3)
{
    // save "locally"
    _alloc3 = alloc3;
    _realloc3 = realloc3;
    _dealloc3 = dealloc3;
    _alloc = (NULL != alloc3) ? cjose_alloc_wrapped : NULL;
    _realloc = (NULL != realloc3) ? cjose_realloc_wrapped : NULL;
    _dealloc = (NULL != dealloc3) ? cjose_dealloc_wrapped : NULL;

    cjose_apply_allocs(void);
}

cjose_alloc_fn_t cjose_get_alloc(void) { return (!_alloc) ? malloc : _alloc; }
cjose_alloc3_fn_t cjose_get_alloc3(void) { return (!_alloc3) ? cjose_alloc3_default : _alloc3; }

cjose_realloc_fn_t cjose_get_realloc(void) { return (!_realloc) ? realloc : _realloc; }
cjose_realloc3_fn_t cjose_get_realloc3(void) { return (!_realloc3) ? cjose_realloc3_default : _realloc3; }

cjose_dealloc_fn_t cjose_get_dealloc(void) { return (!_dealloc) ? free : _dealloc; }
cjose_dealloc3_fn_t cjose_get_dealloc3(void) { return (!_dealloc3) ? cjose_dealloc3_default : _dealloc3; }

int cjose_const_memcmp(const uint8_t *a, const uint8_t *b, const size_t size)
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

    char *result = cjose_get_alloc(void)(sizeof(char) * (len + 1));
    if (!result)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memcpy(result, str, len);
    result[len] = 0;

    return result;
}

json_t *_cjose_json_stringn(const char *value, size_t len, cjose_err *err)
{
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
    cjose_get_dealloc(void)(s);
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
