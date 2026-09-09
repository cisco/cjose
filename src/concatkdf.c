/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2018 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "include/concatkdf_int.h"
#include "include/util_int.h"


#ifdef _WIN32
#include <Winsock2.h>
#include <malloc.h>
#else
#include <arpa/inet.h>
#endif
#include <openssl/evp.h>
#include <string.h>
#include <cjose/base64.h>
#include <cjose/util.h>

////////////////////////////////////////////////////////////////////////////////
static uint8_t *_apply_uint32(const uint32_t value, uint8_t *buffer)
{
    const uint32_t big_endian_int32 = htonl(value);

    memcpy(buffer, &big_endian_int32, 4);
    return buffer + 4;
}

static uint8_t *_apply_lendata(const uint8_t *data, const size_t len, uint8_t *buffer)
{
    uint8_t *ptr = buffer;

    ptr  =_apply_uint32(len, ptr);
    if (0 < len)
    {
        memcpy(ptr, data, len);
        ptr += len;
    }
    return ptr;
}

size_t min_len(size_t a, size_t b)
{
    return (a < b) ? a : b;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_concatkdf_create_otherinfo(const char *alg,
                                      const size_t keylen,
                                      cjose_header_t *hdr,
                                      uint8_t **otherinfo,
                                      size_t *otherinfoLen,
                                      cjose_err *err)
{
    bool result =  false;
    uint8_t *apu = NULL, *apv = NULL;
    size_t apuLen = 0, apvLen = 0;

    // err is optional and may be NULL, so only dereference it when provided.
    // cjose_header_get() records an error only for an invalid header/attr; for a
    // valid hdr and the constant APU/APV attrs an absent field just yields NULL.
    if (NULL != err)
    {
        memset(err, 0, sizeof(cjose_err));
    }
    const char *apuStr = cjose_header_get(hdr, CJOSE_HDR_APU, err);
    const char *apvStr = cjose_header_get(hdr, CJOSE_HDR_APV, err);
    if (NULL != err && CJOSE_ERR_NONE != err->code)
    {
        return false;
    }

    apuLen = (NULL != apuStr) ? strlen(apuStr) : 0;
    if (apuStr != NULL && !cjose_base64url_decode(apuStr, apuLen, &apu, &apuLen, err))
    {
        goto concatkdf_create_otherinfo_finish;
    }
    apvLen = (NULL != apvStr) ? strlen(apvStr) : 0;
    if (apvStr != NULL && !cjose_base64url_decode(apvStr, apvLen, &apv, &apvLen, err))
    {
        goto concatkdf_create_otherinfo_finish;
    }

    const size_t algLen = strlen(alg);
    const size_t bufferLen = (4 + algLen) +
                             (4 + apuLen) +
                             (4 + apvLen) +
                             4;
    uint8_t *buffer = cjose_get_alloc()(bufferLen);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto concatkdf_create_otherinfo_finish;
    }
    uint8_t *ptr = buffer;
    ptr = _apply_lendata((const uint8_t *)alg, algLen, ptr);
    ptr = _apply_lendata(apu, apuLen, ptr);
    ptr = _apply_lendata(apv, apvLen, ptr);
    // final write; the returned (end) pointer is intentionally not stored
    _apply_uint32(keylen, ptr);

    *otherinfoLen = bufferLen;
    *otherinfo = buffer;
    result = true;

concatkdf_create_otherinfo_finish:
    cjose_get_dealloc()(apu);
    cjose_get_dealloc()(apv);

    return result;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t *cjose_concatkdf_derive(const size_t keylen,
                                const uint8_t *ikm,
                                const size_t ikmLen,
                                const uint8_t *otherinfo,
                                const size_t otherinfoLen,
                                cjose_err *err)
{
    uint8_t *derived = NULL;

    uint8_t *buffer = NULL;
    const EVP_MD *dgst = EVP_sha256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto concatkdf_derive_finish;
    }

    const size_t hashlen = EVP_MD_size(dgst);
    const size_t N = (keylen + hashlen - 1) / hashlen;
    buffer = cjose_get_alloc()(keylen);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto concatkdf_derive_finish;
    }

    size_t offset = 0;
    for (int idx = 1; N >= idx; idx++)
    {
        uint8_t counter[4];
        _apply_uint32(idx, counter);

        uint8_t *hash = cjose_get_alloc()(hashlen * sizeof(uint8_t));
        if (NULL == hash)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto concatkdf_derive_finish;
        }

        if (1 != EVP_DigestInit_ex(ctx, dgst, NULL) || 1 != EVP_DigestUpdate(ctx, counter, sizeof(counter))
            || 1 != EVP_DigestUpdate(ctx, ikm, ikmLen) || 1 != EVP_DigestUpdate(ctx, otherinfo, otherinfoLen)
            || 1 != EVP_DigestFinal_ex(ctx, hash, NULL))
        {
            _cjose_cleanse_dealloc(hash, hashlen);
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto concatkdf_derive_finish;
        }

        // copy this digest block into the derived key; the final block may be
        // shorter than hashlen. offset stays < keylen on every iteration, so the
        // remaining count (keylen - offset) cannot underflow.
        // hash holds derived key material; wipe it before returning to the allocator
        size_t amt = keylen - offset;
        memcpy(buffer + offset, hash, min_len(hashlen, amt));
        _cjose_cleanse_dealloc(hash, hashlen);
        offset += hashlen;
    }

    derived = buffer;
    buffer = NULL;

concatkdf_derive_finish:
    EVP_MD_CTX_destroy(ctx);
    _cjose_cleanse_dealloc(buffer, keylen);

    return derived;
}
