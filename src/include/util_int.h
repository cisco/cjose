/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SRC_UTIL_INT_H
#define SRC_UTIL_INT_H

#include <cjose/error.h>

#include <jansson.h>
#include <openssl/opensslv.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
#define CJOSE_OPENSSL_11X
#endif

// the raw key API (EVP_PKEY_new_raw_private_key & co.) and PureEdDSA arrived
// in OpenSSL 1.1.1; the OKP key type and the EdDSA algorithms depend on them
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
#define CJOSE_OPENSSL_111X
#endif

#ifdef _WIN32
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

// NOTE: unlike POSIX strndup this copies exactly len bytes (len < 0 means
// strlen(str)); it does not stop at an embedded NUL, so len must not exceed
// strlen(str) or the copy over-reads str.
char *_cjose_strndup(const char *str, ssize_t len, cjose_err *err);
json_t *_cjose_json_stringn(const char *value, size_t len, cjose_err *err);

void *cjose_alloc3_default(size_t n, const char *file, int line);
void *cjose_realloc3_default(void *p, size_t n, const char *file, int line);
void cjose_dealloc3_default(void *p, const char *file, int line);

void *cjose_alloc_wrapped(size_t n);
void *cjose_realloc_wrapped(void *p, size_t n);
void cjose_dealloc_wrapped(void *p);

void _cjose_cleanse(void *ptr, size_t len);
void _cjose_cleanse_dealloc(void *ptr, size_t len);

#endif // SRC_UTIL_INT_H
