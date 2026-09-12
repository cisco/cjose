/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "include/jwk_int.h"
#include "include/util_int.h"

#include <cjose/base64.h>
#include <cjose/util.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>

// internal data structures

static const char CJOSE_JWK_EC_P_256_STR[] = "P-256";
static const char CJOSE_JWK_EC_SECP_256K1_STR[] = "secp256k1";
static const char CJOSE_JWK_EC_P_384_STR[] = "P-384";
static const char CJOSE_JWK_EC_P_521_STR[] = "P-521";
static const char CJOSE_JWK_KTY_STR[] = "kty";
static const char CJOSE_JWK_KID_STR[] = "kid";
static const char CJOSE_JWK_KTY_EC_STR[] = "EC";
static const char CJOSE_JWK_KTY_RSA_STR[] = "RSA";
static const char CJOSE_JWK_KTY_OCT_STR[] = "oct";
static const char CJOSE_JWK_KTY_OKP_STR[] = "OKP";
static const char CJOSE_JWK_CRV_STR[] = "crv";
static const char CJOSE_JWK_X_STR[] = "x";
static const char CJOSE_JWK_Y_STR[] = "y";
static const char CJOSE_JWK_D_STR[] = "d";
static const char CJOSE_JWK_N_STR[] = "n";
static const char CJOSE_JWK_E_STR[] = "e";
static const char CJOSE_JWK_P_STR[] = "p";
static const char CJOSE_JWK_Q_STR[] = "q";
static const char CJOSE_JWK_DP_STR[] = "dp";
static const char CJOSE_JWK_DQ_STR[] = "dq";
static const char CJOSE_JWK_QI_STR[] = "qi";
static const char CJOSE_JWK_OTH_STR[] = "oth";
static const char CJOSE_JWK_K_STR[] = "k";

static const char *JWK_KTY_NAMES[] = { CJOSE_JWK_KTY_RSA_STR, CJOSE_JWK_KTY_EC_STR, CJOSE_JWK_KTY_OCT_STR, CJOSE_JWK_KTY_OKP_STR };

bool _cjose_jwk_rsa_has_private(const cjose_jwk_t *jwk)
{
    if (jwk == NULL || jwk->kty != CJOSE_JWK_KTY_RSA || jwk->keydata == NULL)
        return false;
    return ((rsa_keydata *)jwk->keydata)->has_private;
}

// interface functions -- Generic

const char *cjose_jwk_name_for_kty(cjose_jwk_kty_t kty, cjose_err *err)
{
    // reject anything outside [CJOSE_JWK_KTY_RSA, CJOSE_JWK_KTY_OKP]; a value
    // below RSA (e.g. a negative sentinel, if the enum is signed) would index
    // JWK_KTY_NAMES out of bounds
    if (kty < CJOSE_JWK_KTY_RSA || CJOSE_JWK_KTY_OKP < kty)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return JWK_KTY_NAMES[kty - CJOSE_JWK_KTY_RSA];
}

cjose_jwk_t *cjose_jwk_retain(cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    if (UINT_MAX == jwk->retained)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
        return NULL;
    }

    ++(jwk->retained);

    return jwk;
}

bool cjose_jwk_release(cjose_jwk_t *jwk)
{
    if (!jwk)
    {
        return false;
    }

    --(jwk->retained);
    if (0 == jwk->retained)
    {
        cjose_get_dealloc()(jwk->kid);
        jwk->kid = NULL;

        // assumes freefunc is set
        if (NULL != jwk->fns->free_func)
        {
            jwk->fns->free_func(jwk);
        }
        jwk = NULL;
    }

    return (NULL != jwk);
}

cjose_jwk_kty_t cjose_jwk_get_kty(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return -1;
    }

    return jwk->kty;
}
size_t cjose_jwk_get_keysize(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return 0;
    }
    return jwk->keysize;
}

void *cjose_jwk_get_keydata(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    return jwk->keydata;
}

const char *cjose_jwk_get_kid(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return jwk->kid;
}

bool cjose_jwk_set_kid(cjose_jwk_t *jwk, const char *kid, size_t len, cjose_err *err)
{
    if (!jwk || !kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    if (jwk->kid)
    {
        cjose_get_dealloc()(jwk->kid);
    }
    jwk->kid = (char *)cjose_get_alloc()(len + 1);
    if (!jwk->kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    // copy exactly len bytes from the caller-supplied (length-delimited, not
    // necessarily NUL-terminated) kid and terminate ourselves; strncpy(len + 1)
    // would read one byte past kid and could leave jwk->kid unterminated.
    memcpy(jwk->kid, kid, len);
    jwk->kid[len] = '\0';
    return true;
}

char *cjose_jwk_to_json(const cjose_jwk_t *jwk, bool priv, cjose_err *err)
{
    char *result = NULL;

    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *json = json_object(), *field = NULL;
    if (!json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }

    // set kty
    const char *kty = cjose_jwk_name_for_kty(jwk->kty, err);
    field = json_string(kty);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    json_object_set(json, "kty", field);
    json_decref(field);
    field = NULL;

    // set kid
    if (NULL != jwk->kid)
    {
        field = json_string(jwk->kid);
        if (!field)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto to_json_cleanup;
        }
        json_object_set(json, CJOSE_JWK_KID_STR, field);
        json_decref(field);
        field = NULL;
    }

    // set public fields
    if (jwk->fns->public_json && !jwk->fns->public_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // set private fields
    if (priv && jwk->fns->private_json && !jwk->fns->private_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // generate the string ...
    char *str_jwk = json_dumps(json, JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (!str_jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    result = _cjose_strndup(str_jwk, -1, err);
    if (!result)
    {
        cjose_get_dealloc()(str_jwk);
        goto to_json_cleanup;
    }
    cjose_get_dealloc()(str_jwk);

to_json_cleanup:
    if (json)
    {
        json_decref(json);
        json = NULL;
    }
    if (field)
    {
        json_decref(field);
        field = NULL;
    }

    return result;
}

//////////////// Octet String ////////////////
// internal data & functions -- Octet String

static void _cjose_jwk_oct_free(cjose_jwk_t *jwk);
static bool _cjose_jwk_oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _cjose_jwk_oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OCT_FNTABLE = { _cjose_jwk_oct_free, _cjose_jwk_oct_public_fields, _cjose_jwk_oct_private_fields };

static cjose_jwk_t *_cjose_jwk_oct_new(uint8_t *buffer, size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = (cjose_jwk_t *)cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    else
    {
        memset(jwk, 0, sizeof(cjose_jwk_t));
        jwk->retained = 1;
        jwk->kty = CJOSE_JWK_KTY_OCT;
        jwk->keysize = keysize;
        jwk->keydata = buffer;
        jwk->fns = &OCT_FNTABLE;
    }

    return jwk;
}

static void _cjose_jwk_oct_free(cjose_jwk_t *jwk)
{
    uint8_t *buffer = (uint8_t *)jwk->keydata;
    jwk->keydata = NULL;
    if (buffer)
    {
        _cjose_cleanse_dealloc(buffer, jwk->keysize / 8);
    }
    cjose_get_dealloc()(jwk);
}

static bool _cjose_jwk_oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err) { return true; }

static bool _cjose_jwk_oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    char *k = NULL;
    size_t klen = 0;
    uint8_t *keydata = (uint8_t *)jwk->keydata;
    size_t keysize = jwk->keysize / 8;

    if (!cjose_base64url_encode(keydata, keysize, &k, &klen, err))
    {
        return false;
    }

    field = _cjose_json_stringn(k, klen, err);
    // k holds the base64url-encoded symmetric key; wipe it before release
    _cjose_cleanse_dealloc(k, klen);
    k = NULL;
    if (!field)
    {
        return false;
    }
    json_object_set(json, "k", field);
    json_decref(field);

    return true;
}

// interface functions -- Octet String

cjose_jwk_t *cjose_jwk_create_oct_random(size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    // resize to bytes
    size_t buffersize = sizeof(uint8_t) * (keysize / 8);

    buffer = (uint8_t *)cjose_get_alloc()(buffersize);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    if (1 != RAND_bytes(buffer, buffersize))
    {
        goto create_oct_failed;
    }

    jwk = _cjose_jwk_oct_new(buffer, keysize, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }
    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_oct_spec(const uint8_t *data, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (NULL == data || 0 == len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    buffer = (uint8_t *)cjose_get_alloc()(len);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    memcpy(buffer, data, len);

    jwk = _cjose_jwk_oct_new(buffer, len * 8, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }

    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

//////////////// Elliptic Curve ////////////////
// internal data & functions -- Elliptic Curve

static void _cjose_jwk_EC_free(cjose_jwk_t *jwk);
static bool _cjose_jwk_EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _cjose_jwk_EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable EC_FNTABLE = { _cjose_jwk_EC_free, _cjose_jwk_EC_public_fields, _cjose_jwk_EC_private_fields };

static inline int _cjose_jwk_ec_nid_for_curve(cjose_jwk_ec_curve crv)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return NID_X9_62_prime256v1;
    case CJOSE_JWK_EC_SECP_256K1:
        return NID_secp256k1;
    case CJOSE_JWK_EC_P_384:
        return NID_secp384r1;
    case CJOSE_JWK_EC_P_521:
        return NID_secp521r1;
    case CJOSE_JWK_EC_INVALID:
        return NID_undef;
    }

    return NID_undef;
}

static inline uint8_t _cjose_jwk_ec_size_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return 32;
    case CJOSE_JWK_EC_SECP_256K1:
        return 32;
    case CJOSE_JWK_EC_P_384:
        return 48;
    case CJOSE_JWK_EC_P_521:
        return 66;
    case CJOSE_JWK_EC_INVALID:
        return 0;
    }

    return 0;
}

static inline const char *_cjose_jwk_ec_name_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return CJOSE_JWK_EC_P_256_STR;
    case CJOSE_JWK_EC_SECP_256K1:
        return CJOSE_JWK_EC_SECP_256K1_STR;
    case CJOSE_JWK_EC_P_384:
        return CJOSE_JWK_EC_P_384_STR;
    case CJOSE_JWK_EC_P_521:
        return CJOSE_JWK_EC_P_521_STR;
    case CJOSE_JWK_EC_INVALID:
        return NULL;
    }

    return NULL;
}

static inline bool _cjose_jwk_ec_curve_from_name(const char *name, cjose_jwk_ec_curve *crv, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_EC_P_256_STR, sizeof(CJOSE_JWK_EC_P_256_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_256;
    }
    else if (strncmp(name, CJOSE_JWK_EC_SECP_256K1_STR, sizeof(CJOSE_JWK_EC_SECP_256K1_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_SECP_256K1;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_384_STR, sizeof(CJOSE_JWK_EC_P_384_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_384;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_521_STR, sizeof(CJOSE_JWK_EC_P_521_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_521;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static inline bool _cjose_jwk_kty_from_name(const char *name, cjose_jwk_kty_t *kty, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_KTY_EC_STR, sizeof(CJOSE_JWK_KTY_EC_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_EC;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_RSA_STR, sizeof(CJOSE_JWK_KTY_RSA_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_RSA;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_OCT_STR, sizeof(CJOSE_JWK_KTY_OCT_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OCT;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_OKP_STR, sizeof(CJOSE_JWK_KTY_OKP_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OKP;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static const char *_cjose_jwk_ec_group_name_for_curve(cjose_jwk_ec_curve crv)
{
    const int nid = _cjose_jwk_ec_nid_for_curve(crv);
    return nid == NID_undef ? NULL : OBJ_nid2sn(nid);
}

static EVP_PKEY *_cjose_jwk_EC_from_params(const char *group_name, const uint8_t *pub, size_t pub_len, const BIGNUM *priv)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL || OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len) != 1
        || (priv != NULL && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv) != 1))
    {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &key, priv == NULL ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params) != 1)
    {
        EVP_PKEY_free(key);
        key = NULL;
    }
    else
    {
        check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        if (check_ctx == NULL || (priv == NULL ? EVP_PKEY_public_check(check_ctx) : EVP_PKEY_check(check_ctx)) != 1)
        {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }

cleanup:
    EVP_PKEY_CTX_free(check_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return key;
}

static cjose_jwk_t *_cjose_jwk_EC_new(cjose_jwk_ec_curve crv, EVP_PKEY *key, bool has_private, cjose_err *err)
{
    ec_keydata *keydata = cjose_get_alloc()(sizeof(ec_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = key;
    keydata->has_private = has_private;

    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        cjose_get_dealloc()(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_EC;
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_EC_SECP_256K1:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_EC_P_384:
        jwk->keysize = 384;
        break;
    case CJOSE_JWK_EC_P_521:
        jwk->keysize = 521;
        break;
    case CJOSE_JWK_EC_INVALID:
        // should never happen
        jwk->keysize = 0;
        break;
    }
    jwk->keydata = keydata;
    jwk->fns = &EC_FNTABLE;

    return jwk;
}

static void _cjose_jwk_EC_free(cjose_jwk_t *jwk)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EVP_PKEY *key = keydata->key;
        keydata->key = NULL;
        if (key)
        {
            EVP_PKEY_free(key);
        }
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static bool _cjose_jwk_EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _cjose_jwk_ec_size_for_curve(keydata->crv, err);

    // output the curve
    field = json_string(_cjose_jwk_ec_name_for_curve(keydata->crv, err));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    uint8_t pub[1 + 2 * 66];
    size_t pub_len = 0;
    group = EC_GROUP_new_by_curve_name(_cjose_jwk_ec_nid_for_curve(keydata->crv));
    point = group == NULL ? NULL : EC_POINT_new(group);
    bnX = BN_new();
    bnY = BN_new();
    if (EVP_PKEY_get_octet_string_param(keydata->key, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &pub_len) != 1 || group == NULL
        || point == NULL || bnX == NULL || bnY == NULL || EC_POINT_oct2point(group, point, pub, pub_len, NULL) != 1
        || EC_POINT_get_affine_coordinates(group, point, bnX, bnY, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    // output the x coordinate
    if (BN_bn2binpad(bnX, buffer, numsize) != numsize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    // output the y coordinate
    if (BN_bn2binpad(bnY, buffer, numsize) != numsize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "y", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_ec_to_string_cleanup:
    if (field)
    {
        json_decref(field);
    }
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
    }
    BN_free(bnX);
    BN_free(bnY);
    EC_POINT_free(point);
    EC_GROUP_free(group);

    return result;
}

static bool _cjose_jwk_EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    BIGNUM *bnD = NULL;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0, offset = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _cjose_jwk_ec_size_for_curve(keydata->crv, err);

    // short circuit if this is a public-only key
    if (!keydata->has_private)
    {
        return true;
    }
    if (EVP_PKEY_get_bn_param(keydata->key, OSSL_PKEY_PARAM_PRIV_KEY, &bnD) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    if (BN_is_zero(bnD))
    {
        BN_clear_free(bnD);
        return true;
    }

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    offset = numsize - BN_num_bytes(bnD);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnD, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;

    result = true;

_ec_to_string_cleanup:
    // buffer and b64u hold the raw / base64url-encoded private key 'd';
    // wipe them before release on the success path as well as the
    // _cjose_json_stringn failure path (where b64u would otherwise leak)
    _cjose_cleanse_dealloc(buffer, numsize);
    _cjose_cleanse_dealloc(b64u, len);
    BN_clear_free(bnD);

    return result;
}

// interface functions -- Elliptic Curve

cjose_jwk_t *cjose_jwk_create_EC_random(cjose_jwk_ec_curve crv, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    const char *group_name = _cjose_jwk_ec_group_name_for_curve(crv);
    OSSL_PARAM params[] = { OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, 0), OSSL_PARAM_END };

    if (!group_name)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_CTX_set_params(ctx, params) != 1
        || EVP_PKEY_keygen(ctx, &key) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    jwk = _cjose_jwk_EC_new(crv, key, true, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    key = NULL;
    EVP_PKEY_CTX_free(ctx);
    return jwk;

create_EC_failed:
    if (jwk)
    {
        cjose_get_dealloc()(jwk);
        jwk = NULL;
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_EC_spec(const cjose_jwk_ec_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *bnD = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    uint8_t pub[1 + 2 * 66];
    size_t pub_len = 0;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool hasPub = ((NULL != spec->x && 0 < spec->xlen) && (NULL != spec->y && 0 < spec->ylen));
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    const char *group_name = _cjose_jwk_ec_group_name_for_curve(spec->crv);
    group = EC_GROUP_new_by_curve_name(_cjose_jwk_ec_nid_for_curve(spec->crv));
    if (NULL == group || NULL == group_name)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    // convert d from octet string to BIGNUM
    if (hasPriv)
    {
        bnD = BN_bin2bn(spec->d, spec->dlen, NULL);
        if (NULL == bnD)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        // calculate public key from private
        Q = EC_POINT_new(group);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        if (1 != EC_POINT_mul(group, Q, bnD, NULL, NULL, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        // public key is set below
        // ignore provided public key!
        hasPub = false;
    }
    if (hasPub)
    {
        Q = EC_POINT_new(group);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        bnX = BN_bin2bn(spec->x, spec->xlen, NULL);
        bnY = BN_bin2bn(spec->y, spec->ylen, NULL);
        if (!bnX || !bnY)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_set_affine_coordinates(group, Q, bnX, bnY, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_is_on_curve(group, Q, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_EC_failed;
        }
    }

    pub_len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    if (pub_len != 1 + 2 * _cjose_jwk_ec_size_for_curve(spec->crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    key = _cjose_jwk_EC_from_params(group_name, pub, pub_len, bnD);
    if (key == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    jwk = _cjose_jwk_EC_new(spec->crv, key, hasPriv, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    // jump to cleanup
    goto create_EC_cleanup;

create_EC_failed:
    if (jwk)
    {
        cjose_get_dealloc()(jwk);
        jwk = NULL;
    }
    EVP_PKEY_free(key);

create_EC_cleanup:
    if (Q)
    {
        EC_POINT_free(Q);
        Q = NULL;
    }
    EC_GROUP_free(group);
    if (bnD)
    {
        BN_free(bnD);
        bnD = NULL;
    }
    if (bnX)
    {
        BN_free(bnX);
        bnX = NULL;
    }
    if (bnY)
    {
        BN_free(bnY);
        bnY = NULL;
    }

    return jwk;
}

cjose_jwk_ec_curve cjose_jwk_EC_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jwk || CJOSE_JWK_KTY_EC != cjose_jwk_get_kty(jwk, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return CJOSE_JWK_EC_INVALID;
    }

    ec_keydata *keydata = jwk->keydata;
    return keydata->crv;
}

//////////////// Octet Key Pair ////////////////
// internal data & functions -- Octet Key Pair (RFC 8037)

static const char CJOSE_JWK_OKP_ED25519_STR[] = "Ed25519";
static const char CJOSE_JWK_OKP_ED448_STR[] = "Ed448";
static const char CJOSE_JWK_OKP_X25519_STR[] = "X25519";
static const char CJOSE_JWK_OKP_X448_STR[] = "X448";

static void _cjose_jwk_OKP_free(cjose_jwk_t *jwk);
static bool _cjose_jwk_OKP_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _cjose_jwk_OKP_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OKP_FNTABLE = { _cjose_jwk_OKP_free, _cjose_jwk_OKP_public_fields, _cjose_jwk_OKP_private_fields };

static inline int _cjose_jwk_okp_nid_for_curve(cjose_jwk_okp_curve crv)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return NID_ED25519;
    case CJOSE_JWK_OKP_ED448:
        return NID_ED448;
    case CJOSE_JWK_OKP_X25519:
        return NID_X25519;
    case CJOSE_JWK_OKP_X448:
        return NID_X448;
    case CJOSE_JWK_OKP_INVALID:
        return NID_undef;
    }

    return NID_undef;
}

// the fixed size of both the raw public key "x" and the raw private key "d"
// (RFC 8032 sections 5.1.5 and 5.2.5, RFC 7748 section 5)
static inline size_t _cjose_jwk_okp_size_for_curve(cjose_jwk_okp_curve crv)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return 32;
    case CJOSE_JWK_OKP_ED448:
        return 57;
    case CJOSE_JWK_OKP_X25519:
        return 32;
    case CJOSE_JWK_OKP_X448:
        return 56;
    case CJOSE_JWK_OKP_INVALID:
        return 0;
    }

    return 0;
}

static inline const char *_cjose_jwk_okp_name_for_curve(cjose_jwk_okp_curve crv)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return CJOSE_JWK_OKP_ED25519_STR;
    case CJOSE_JWK_OKP_ED448:
        return CJOSE_JWK_OKP_ED448_STR;
    case CJOSE_JWK_OKP_X25519:
        return CJOSE_JWK_OKP_X25519_STR;
    case CJOSE_JWK_OKP_X448:
        return CJOSE_JWK_OKP_X448_STR;
    case CJOSE_JWK_OKP_INVALID:
        return NULL;
    }

    return NULL;
}

static inline bool _cjose_jwk_okp_curve_from_name(const char *name, cjose_jwk_okp_curve *crv)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_OKP_ED25519_STR, sizeof(CJOSE_JWK_OKP_ED25519_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_ED25519;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_ED448_STR, sizeof(CJOSE_JWK_OKP_ED448_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_ED448;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_X25519_STR, sizeof(CJOSE_JWK_OKP_X25519_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_X25519;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_X448_STR, sizeof(CJOSE_JWK_OKP_X448_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_X448;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static cjose_jwk_t *_cjose_jwk_OKP_new(cjose_jwk_okp_curve crv, EVP_PKEY *pkey, bool has_private, cjose_err *err)
{
    okp_keydata *keydata = cjose_get_alloc()(sizeof(okp_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = pkey;
    keydata->has_private = has_private;

    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        cjose_get_dealloc()(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_OKP;
    jwk->keysize = _cjose_jwk_okp_size_for_curve(crv) * 8;
    jwk->keydata = keydata;
    jwk->fns = &OKP_FNTABLE;

    return jwk;
}

static void _cjose_jwk_OKP_free(cjose_jwk_t *jwk)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EVP_PKEY_free(keydata->key);
        keydata->key = NULL;
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static bool _cjose_jwk_OKP_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0;
    json_t *field = NULL;
    bool result = false;

    // the raw public key has the fixed size of the curve
    size_t numsize = _cjose_jwk_okp_size_for_curve(keydata->crv);

    // output the curve
    field = json_string(_cjose_jwk_okp_name_for_curve(keydata->crv));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    // obtain the raw public key
    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _okp_to_string_cleanup;
    }
    len = numsize;
    if (1 != EVP_PKEY_get_raw_public_key(keydata->key, buffer, &len) || len != numsize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _okp_to_string_cleanup;
    }

    // output the public key x
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _okp_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;

    result = true;

_okp_to_string_cleanup:
    cjose_get_dealloc()(buffer);
    cjose_get_dealloc()(b64u);

    return result;
}

static bool _cjose_jwk_OKP_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0;
    size_t b64u_len = 0;
    json_t *field = NULL;
    int rc = 0;
    bool result = false;

    // the raw private key has the fixed size of the curve
    size_t numsize = _cjose_jwk_okp_size_for_curve(keydata->crv);

    // Short circuit if the JWK was created without private key material.
    if (!keydata->has_private)
    {
        return true;
    }

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _okp_to_string_cleanup;
    }

    len = numsize;
    rc = EVP_PKEY_get_raw_private_key(keydata->key, buffer, &len);
    if (1 != rc)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _okp_to_string_cleanup;
    }
    if (len != numsize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _okp_to_string_cleanup;
    }

    // output the private key d
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &b64u_len, err))
    {
        goto _okp_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, b64u_len, err);
    if (!field)
    {
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;

    result = true;

_okp_to_string_cleanup:
    // buffer and b64u hold the raw / base64url-encoded private key 'd';
    // wipe them before release
    _cjose_cleanse_dealloc(buffer, numsize);
    _cjose_cleanse_dealloc(b64u, b64u_len);

    return result;
}

// interface functions -- Octet Key Pair

cjose_jwk_t *cjose_jwk_create_OKP_random(cjose_jwk_okp_curve crv, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    int nid = _cjose_jwk_okp_nid_for_curve(crv);
    if (NID_undef == nid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_OKP_random_cleanup;
    }

    ctx = EVP_PKEY_CTX_new_id(nid, NULL);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_random_cleanup;
    }
    if (1 != EVP_PKEY_keygen_init(ctx) || 1 != EVP_PKEY_keygen(ctx, &pkey))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_random_cleanup;
    }

    jwk = _cjose_jwk_OKP_new(crv, pkey, true, err);
    if (NULL == jwk)
    {
        goto create_OKP_random_cleanup;
    }
    // the jwk owns the key now
    pkey = NULL;

create_OKP_random_cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return jwk;
}

cjose_jwk_t *cjose_jwk_create_OKP_spec(const cjose_jwk_okp_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *pkey = NULL;
    uint8_t *pub = NULL;
    size_t pub_len = 0;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    int nid = _cjose_jwk_okp_nid_for_curve(spec->crv);
    size_t numsize = _cjose_jwk_okp_size_for_curve(spec->crv);
    if (NID_undef == nid || 0 == numsize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool hasPub = (NULL != spec->x && 0 < spec->xlen);
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // the raw keys have the fixed size of the curve (RFC 8037 section 2);
    // check that up front instead of relying on OpenSSL to reject them
    if ((hasPriv && spec->dlen != numsize) || (hasPub && spec->xlen != numsize))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    if (hasPriv)
    {
        pkey = EVP_PKEY_new_raw_private_key(nid, NULL, spec->d, spec->dlen);
        if (NULL == pkey)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_OKP_spec_cleanup;
        }

        // OpenSSL derives the public key from the private key; when a public
        // key is supplied as well it must be that one
        if (hasPub)
        {
            pub = cjose_get_alloc()(numsize);
            if (NULL == pub)
            {
                CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
                goto create_OKP_spec_cleanup;
            }
            pub_len = numsize;
            if (1 != EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) || pub_len != numsize)
            {
                CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
                goto create_OKP_spec_cleanup;
            }
            if (0 != cjose_const_memcmp(pub, spec->x, numsize))
            {
                CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
                goto create_OKP_spec_cleanup;
            }
        }
    }
    else
    {
        pkey = EVP_PKEY_new_raw_public_key(nid, NULL, spec->x, spec->xlen);
        if (NULL == pkey)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_OKP_spec_cleanup;
        }
    }

    jwk = _cjose_jwk_OKP_new(spec->crv, pkey, hasPriv, err);
    if (NULL == jwk)
    {
        goto create_OKP_spec_cleanup;
    }
    // the jwk owns the key now
    pkey = NULL;

create_OKP_spec_cleanup:
    EVP_PKEY_free(pkey);
    cjose_get_dealloc()(pub);

    return jwk;
}

cjose_jwk_okp_curve cjose_jwk_OKP_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jwk || CJOSE_JWK_KTY_OKP != cjose_jwk_get_kty(jwk, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return CJOSE_JWK_OKP_INVALID;
    }

    okp_keydata *keydata = jwk->keydata;
    return keydata->crv;
}

//////////////// RSA ////////////////
// internal data & functions -- RSA

static void _cjose_jwk_RSA_free(cjose_jwk_t *jwk);
static bool _cjose_jwk_RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _cjose_jwk_RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable RSA_FNTABLE = { _cjose_jwk_RSA_free, _cjose_jwk_RSA_public_fields, _cjose_jwk_RSA_private_fields };

static inline cjose_jwk_t *_cjose_jwk_RSA_new(EVP_PKEY *key,
                                              bool has_private,
                                              bool has_factors,
                                              bool has_crt,
                                              BIGNUM *p,
                                              BIGNUM *q,
                                              BIGNUM *dp,
                                              BIGNUM *dq,
                                              BIGNUM *qi,
                                              cjose_err *err)
{
    rsa_keydata *keydata = cjose_get_alloc()(sizeof(rsa_keydata));
    if (!keydata)
    {
        EVP_PKEY_free(key);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(dp);
        BN_clear_free(dq);
        BN_clear_free(qi);
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->key = key;
    keydata->has_private = has_private;
    keydata->has_factors = has_factors;
    keydata->has_crt = has_crt;
    keydata->p = p;
    keydata->q = q;
    keydata->dp = dp;
    keydata->dq = dq;
    keydata->qi = qi;
    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        EVP_PKEY_free(key);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(dp);
        BN_clear_free(dq);
        BN_clear_free(qi);
        cjose_get_dealloc()(keydata);
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_RSA;
    jwk->keysize = (size_t)EVP_PKEY_get_size(key) * 8;
    jwk->keydata = keydata;
    jwk->fns = &RSA_FNTABLE;

    return jwk;
}

static void _cjose_jwk_RSA_free(cjose_jwk_t *jwk)
{
    rsa_keydata *keydata = (rsa_keydata *)jwk->keydata;
    jwk->keydata = NULL;
    if (keydata)
    {
        EVP_PKEY_free(keydata->key);
        BN_clear_free(keydata->p);
        BN_clear_free(keydata->q);
        BN_clear_free(keydata->dp);
        BN_clear_free(keydata->dq);
        BN_clear_free(keydata->qi);
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static inline bool _cjose_jwk_RSA_json_field(const BIGNUM *param, const char *name, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    uint8_t *data = NULL;
    char *b64u = NULL;
    size_t datalen = 0, b64ulen = 0;
    bool result = false;

    if (!param)
    {
        return true;
    }

    datalen = BN_num_bytes(param);
    data = cjose_get_alloc()(sizeof(uint8_t) * datalen);
    if (!data)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto RSA_json_field_cleanup;
    }
    BN_bn2bin(param, data);
    if (!cjose_base64url_encode(data, datalen, &b64u, &b64ulen, err))
    {
        goto RSA_json_field_cleanup;
    }
    field = _cjose_json_stringn(b64u, b64ulen, err);
    if (!field)
    {
        goto RSA_json_field_cleanup;
    }
    json_object_set(json, name, field);
    json_decref(field);
    field = NULL;
    result = true;

RSA_json_field_cleanup:
    // data / b64u may hold a private key component (d, p, q, dp, dq, qi);
    // wipe them before release (harmless for the public n and e)
    _cjose_cleanse_dealloc(b64u, b64ulen);
    b64u = NULL;
    _cjose_cleanse_dealloc(data, datalen);
    data = NULL;

    return result;
}

static bool _cjose_jwk_RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    EVP_PKEY *key = _cjose_jwk_rsa_key(jwk);
    BIGNUM *rsa_n = NULL, *rsa_e = NULL;
    bool result = false;

    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &rsa_n) != 1
        || EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &rsa_e) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cleanup;
    }

    if (!_cjose_jwk_RSA_json_field(rsa_e, "e", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_n, "n", json, err))
    {
        goto cleanup;
    }

    result = true;

cleanup:
    BN_free(rsa_n);
    BN_free(rsa_e);
    return result;
}

static bool _cjose_jwk_RSA_get_private_param(EVP_PKEY *key, const BIGNUM *stored, const char *name, BIGNUM **param, cjose_err *err)
{
    if (stored != NULL)
    {
        *param = BN_dup(stored);
        if (*param == NULL)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            return false;
        }
        return true;
    }
    if (EVP_PKEY_get_bn_param(key, name, param) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    return true;
}

static bool _cjose_jwk_RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    rsa_keydata *keydata = (rsa_keydata *)jwk->keydata;
    EVP_PKEY *key = keydata->key;
    BIGNUM *rsa_d = NULL, *rsa_p = NULL, *rsa_q = NULL;
    BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;
    bool result = false;

    if (!keydata->has_private)
        return true;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &rsa_d) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto cleanup;
    }
    if (keydata->has_factors
        && (!_cjose_jwk_RSA_get_private_param(key, keydata->p, OSSL_PKEY_PARAM_RSA_FACTOR1, &rsa_p, err)
            || !_cjose_jwk_RSA_get_private_param(key, keydata->q, OSSL_PKEY_PARAM_RSA_FACTOR2, &rsa_q, err)))
        goto cleanup;
    if (keydata->has_crt
        && (!_cjose_jwk_RSA_get_private_param(key, keydata->dp, OSSL_PKEY_PARAM_RSA_EXPONENT1, &rsa_dmp1, err)
            || !_cjose_jwk_RSA_get_private_param(key, keydata->dq, OSSL_PKEY_PARAM_RSA_EXPONENT2, &rsa_dmq1, err)
            || !_cjose_jwk_RSA_get_private_param(key, keydata->qi, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &rsa_iqmp, err)))
        goto cleanup;

    if (!_cjose_jwk_RSA_json_field(rsa_d, "d", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_p, "p", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_q, "q", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_dmp1, "dp", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_dmq1, "dq", json, err))
    {
        goto cleanup;
    }
    if (!_cjose_jwk_RSA_json_field(rsa_iqmp, "qi", json, err))
    {
        goto cleanup;
    }

    result = true;

cleanup:
    BN_clear_free(rsa_d);
    BN_clear_free(rsa_p);
    BN_clear_free(rsa_q);
    BN_clear_free(rsa_dmp1);
    BN_clear_free(rsa_dmq1);
    BN_clear_free(rsa_iqmp);
    return result;
}

// interface functions -- RSA
static const uint8_t *DEFAULT_E_DAT = (const uint8_t *)"\x01\x00\x01";
static const size_t DEFAULT_E_LEN = 3;

cjose_jwk_t *cjose_jwk_create_RSA_random(size_t keysize, const uint8_t *e, size_t elen, cjose_err *err)
{
    // RFC 7518 §3.3 requires minimum 2048-bit RSA modulus for RS*/PS*/RSA-OAEP/RSA1_5
    if (keysize < 2048)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == e || 0 >= elen)
    {
        e = DEFAULT_E_DAT;
        elen = DEFAULT_E_LEN;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *bn = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    bn = BN_bin2bn(e, elen, NULL);
    if (!bn)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) != 1
        || EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) != 1 || EVP_PKEY_keygen(ctx, &key) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    BN_free(bn);
    EVP_PKEY_CTX_free(ctx);
    return _cjose_jwk_RSA_new(key, true, true, true, NULL, NULL, NULL, NULL, NULL, err);

create_RSA_random_failed:
    if (bn)
    {
        BN_free(bn);
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

cjose_jwk_t *cjose_jwk_create_RSA_spec(const cjose_jwk_rsa_keyspec *spec, cjose_err *err)
{
    if (NULL == spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPub = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->e && 0 < spec->elen);
    bool hasPriv = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->d && 0 < spec->dlen);
    if (!hasPub && !hasPriv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // RFC 7518 §3.3 requires minimum 2048-bit RSA modulus for RS*/PS*/RSA-OAEP/RSA1_5
    BIGNUM *n_bn = BN_bin2bn(spec->n, spec->nlen, NULL);
    if (NULL == n_bn)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    if (BN_num_bits(n_bn) < 2048)
    {
        BN_free(n_bn);
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    BN_free(n_bn);

    if (!hasPub || (hasPriv && (NULL == spec->e || 0 == spec->elen)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool has_factors = hasPriv && ((spec->p != NULL && spec->plen > 0) || (spec->q != NULL && spec->qlen > 0));
    bool has_crt = hasPriv
                   && ((spec->dp != NULL && spec->dplen > 0) || (spec->dq != NULL && spec->dqlen > 0)
                       || (spec->qi != NULL && spec->qilen > 0));
    if ((has_factors && (spec->p == NULL || spec->plen == 0 || spec->q == NULL || spec->qlen == 0))
        || (has_crt
            && (spec->dp == NULL || spec->dplen == 0 || spec->dq == NULL || spec->dqlen == 0 || spec->qi == NULL
                || spec->qilen == 0)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = BN_bin2bn(spec->n, spec->nlen, NULL);
    BIGNUM *e = BN_bin2bn(spec->e, spec->elen, NULL);
    BIGNUM *d = hasPriv ? BN_bin2bn(spec->d, spec->dlen, NULL) : NULL;
    BIGNUM *p = has_factors ? BN_bin2bn(spec->p, spec->plen, NULL) : NULL;
    BIGNUM *q = has_factors ? BN_bin2bn(spec->q, spec->qlen, NULL) : NULL;
    BIGNUM *dp = has_crt ? BN_bin2bn(spec->dp, spec->dplen, NULL) : NULL;
    BIGNUM *dq = has_crt ? BN_bin2bn(spec->dq, spec->dqlen, NULL) : NULL;
    BIGNUM *qi = has_crt ? BN_bin2bn(spec->qi, spec->qilen, NULL) : NULL;
    bool has_complete_crt = has_factors && has_crt;

    bld = OSSL_PARAM_BLD_new();
    if (n == NULL || e == NULL || (hasPriv && d == NULL) || (has_factors && (p == NULL || q == NULL))
        || (has_crt && (dp == NULL || dq == NULL || qi == NULL)) || bld == NULL
        || OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1 || OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1
        || (d != NULL && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) != 1)
        || (has_complete_crt && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) != 1)
        || (has_complete_crt && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) != 1)
        || (has_complete_crt && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp) != 1)
        || (has_complete_crt && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq) != 1)
        || (has_complete_crt && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi) != 1))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_spec_failed;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &key, hasPriv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_RSA_spec_failed;
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(n);
    BN_free(e);
    BN_clear_free(d);
    return _cjose_jwk_RSA_new(key, hasPriv, has_factors, has_crt, p, q, dp, dq, qi, err);

create_RSA_spec_failed:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(dp);
    BN_clear_free(dq);
    BN_clear_free(qi);
    return NULL;
}

//////////////// Import ////////////////
// internal data & functions -- JWK key import

static const char *_cjose_jwk_get_json_object_string_attribute(json_t *json, const char *key, cjose_err *err)
{
    const char *attr_str = NULL;
    json_t *attr_json = json_object_get(json, key);
    if (NULL != attr_json)
    {
        attr_str = json_string_value(attr_json);
    }
    return attr_str;
}

/**
 * Internal helper function for extracing an octet string from a base64url
 * encoded field.  Caller provides the json object, the attribute key,
 * and an expected length for the octet string.  On successful decoding,
 * this will return a newly allocated buffer with the decoded octet string
 * of the expected length.
 *
 * Note: caller is responsible for freeing the buffer returned by this function.
 *
 * \param[in]     json the JSON object from which to read the attribute.
 * \param[in]     key the name of the attribute to be decoded.
 * \param[out]    pointer to buffer of octet string (if decoding succeeds).
 * \param[in/out] in as the expected length of the attribute, out as the
 *                actual decoded length.  Note, this method succeeds only
 *                if the actual decoded length matches the expected length.
 *                If the in-value is 0 this indicates there is no particular
 *                expected length (i.e. any length is ok).
 * \returns true  if attribute is either not present or successfully decoded.
 *                false otherwise.
 */
static bool _cjose_jwk_decode_json_object_base64url_attribute(
    json_t *jwk_json, const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
{
    // get the base64url encoded string value of the attribute (if any)
    const char *str = _cjose_jwk_get_json_object_string_attribute(jwk_json, key, err);
    if (str == NULL || strlen(str) == 0)
    {
        *buflen = 0;
        *buffer = NULL;
        return true;
    }

    // if a particular decoded length is expected, check for that
    if (*buflen != 0)
    {
        const char *end = NULL;
        for (end = str + strlen(str) - 1; *end == '=' && end > str; --end)
            ;
        size_t unpadded_len = end + 1 - str - ((*end == '=') ? 1 : 0);
        // number of unpadded base64url characters for *buflen bytes,
        // i.e. ceil(4 * buflen / 3) computed with integer arithmetic
        size_t expected_len = (4 * (*buflen) + 2) / 3;

        if (expected_len != unpadded_len)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            *buflen = 0;
            *buffer = NULL;
            return false;
        }
    }

    // decode the base64url encoded string to the allocated buffer
    if (!cjose_base64url_decode(str, strlen(str), buffer, buflen, err))
    {
        *buflen = 0;
        *buffer = NULL;
        return false;
    }

    return true;
}

// RFC 7518 section 6.3.2: a private member that is present but carries no
// value is a malformed key, not a public one, so it must not be read as absent
static bool _cjose_jwk_decode_private_attribute(json_t *jwk_json, const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
{
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, key, buffer, buflen, err))
    {
        return false;
    }
    // base64url padding on its own decodes to nothing, so the buffer can be
    // present and still carry no octets
    if (NULL != json_object_get(jwk_json, key) && (NULL == *buffer || 0 == *buflen))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    return true;
}

static cjose_jwk_t *_cjose_jwk_import_EC(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *y_buffer = NULL;
    uint8_t *d_buffer = NULL;
    size_t x_buflen = 0;
    size_t y_buflen = 0;
    size_t d_buflen = 0;

    // get the value of the crv attribute
    const char *crv_str = _cjose_jwk_get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the curve identifer for the curve named by crv
    cjose_jwk_ec_curve crv;
    if (!_cjose_jwk_ec_curve_from_name(crv_str, &crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the x coordinate
    x_buflen = (size_t)_cjose_jwk_ec_size_for_curve(crv, err);
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the y coordinate
    y_buflen = (size_t)_cjose_jwk_ec_size_for_curve(crv, err);
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Y_STR, &y_buffer, &y_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the private key d; a "d" that is present but
    // carries no value is a malformed key, not a public one (the OKP import
    // makes the same distinction)
    d_buflen = (size_t)_cjose_jwk_ec_size_for_curve(crv, err);
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err)
        || (NULL != json_object_get(jwk_json, CJOSE_JWK_D_STR) && NULL == d_buffer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // create an ec keyspec
    cjose_jwk_ec_keyspec ec_keyspec;
    memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));
    ec_keyspec.crv = crv;
    ec_keyspec.x = x_buffer;
    ec_keyspec.xlen = x_buflen;
    ec_keyspec.y = y_buffer;
    ec_keyspec.ylen = y_buflen;
    ec_keyspec.d = d_buffer;
    ec_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_EC_spec(&ec_keyspec, err);

import_EC_cleanup:
    if (NULL != x_buffer)
    {
        cjose_get_dealloc()(x_buffer);
    }
    if (NULL != y_buffer)
    {
        cjose_get_dealloc()(y_buffer);
    }
    // d is the private key -> wipe the decoded copy before release
    if (NULL != d_buffer)
    {
        _cjose_cleanse_dealloc(d_buffer, d_buflen);
    }

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_RSA(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *n_buffer = NULL;
    uint8_t *e_buffer = NULL;
    uint8_t *d_buffer = NULL;
    uint8_t *p_buffer = NULL;
    uint8_t *q_buffer = NULL;
    uint8_t *dp_buffer = NULL;
    uint8_t *dq_buffer = NULL;
    uint8_t *qi_buffer = NULL;
    size_t n_buflen = 0;
    size_t e_buflen = 0;
    size_t d_buflen = 0;
    size_t p_buflen = 0;
    size_t q_buflen = 0;
    size_t dp_buflen = 0;
    size_t dq_buflen = 0;
    size_t qi_buflen = 0;

    // cjose supports only two-prime RSA keys; RFC 7518 section 6.3.2.7
    // requires consumers that do not support multi-prime keys not to use a
    // key carrying the "oth" parameter
    if (NULL != json_object_get(jwk_json, CJOSE_JWK_OTH_STR))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of n (buflen = 0 means no particular expected len)
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_N_STR, &n_buffer, &n_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of e
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_E_STR, &e_buffer, &e_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of d
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of p
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_P_STR, &p_buffer, &p_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of q
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_Q_STR, &q_buffer, &q_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dp
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_DP_STR, &dp_buffer, &dp_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dq
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_DQ_STR, &dq_buffer, &dq_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of qi
    if (!_cjose_jwk_decode_private_attribute(jwk_json, CJOSE_JWK_QI_STR, &qi_buffer, &qi_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // create an rsa keyspec
    cjose_jwk_rsa_keyspec rsa_keyspec;
    memset(&rsa_keyspec, 0, sizeof(cjose_jwk_rsa_keyspec));
    rsa_keyspec.n = n_buffer;
    rsa_keyspec.nlen = n_buflen;
    rsa_keyspec.e = e_buffer;
    rsa_keyspec.elen = e_buflen;
    rsa_keyspec.d = d_buffer;
    rsa_keyspec.dlen = d_buflen;
    rsa_keyspec.p = p_buffer;
    rsa_keyspec.plen = p_buflen;
    rsa_keyspec.q = q_buffer;
    rsa_keyspec.qlen = q_buflen;
    rsa_keyspec.dp = dp_buffer;
    rsa_keyspec.dplen = dp_buflen;
    rsa_keyspec.dq = dq_buffer;
    rsa_keyspec.dqlen = dq_buflen;
    rsa_keyspec.qi = qi_buffer;
    rsa_keyspec.qilen = qi_buflen;

    // create the jwk
    jwk = cjose_jwk_create_RSA_spec(&rsa_keyspec, err);

import_RSA_cleanup:
    // n and e are public; the remaining decoded components are private -> wipe
    cjose_get_dealloc()(n_buffer);
    cjose_get_dealloc()(e_buffer);
    _cjose_cleanse_dealloc(d_buffer, d_buflen);
    _cjose_cleanse_dealloc(p_buffer, p_buflen);
    _cjose_cleanse_dealloc(q_buffer, q_buflen);
    _cjose_cleanse_dealloc(dp_buffer, dp_buflen);
    _cjose_cleanse_dealloc(dq_buffer, dq_buflen);
    _cjose_cleanse_dealloc(qi_buffer, qi_buflen);

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_oct(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *k_buffer = NULL;

    // get the decoded value of k (buflen = 0 means no particular expected len)
    size_t k_buflen = 0;
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_K_STR, &k_buffer, &k_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_oct_cleanup;
    }

    // create the jwk
    jwk = cjose_jwk_create_oct_spec(k_buffer, k_buflen, err);

import_oct_cleanup:
    // k is secret symmetric key material -> wipe the decoded copy
    _cjose_cleanse_dealloc(k_buffer, k_buflen);

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_OKP(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *d_buffer = NULL;
    size_t x_buflen = 0;
    size_t d_buflen = 0;

    // get the value of the crv attribute
    const char *crv_str = _cjose_jwk_get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the curve identifier for the curve named by crv
    cjose_jwk_okp_curve crv;
    if (!_cjose_jwk_okp_curve_from_name(crv_str, &crv))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the decoded value of the public key x (of the fixed size of the
    // curve); x is REQUIRED for every OKP key (RFC 8037 section 2), and the
    // decoder treats a missing, empty or non-string attribute alike, so a
    // decoded value must have come out of it
    x_buflen = _cjose_jwk_okp_size_for_curve(crv);
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err)
        || NULL == x_buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the decoded value of the private key d (of the fixed size of the
    // curve); d is REQUIRED for a private key and MUST NOT be present for a
    // public key (RFC 8037 section 2), so when the attribute is there it must
    // decode to a key of the right size instead of quietly making a public key
    d_buflen = _cjose_jwk_okp_size_for_curve(crv);
    if (!_cjose_jwk_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err)
        || (NULL != json_object_get(jwk_json, CJOSE_JWK_D_STR) && NULL == d_buffer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // create an okp keyspec
    cjose_jwk_okp_keyspec okp_keyspec;
    memset(&okp_keyspec, 0, sizeof(cjose_jwk_okp_keyspec));
    okp_keyspec.crv = crv;
    okp_keyspec.x = x_buffer;
    okp_keyspec.xlen = x_buflen;
    okp_keyspec.d = d_buffer;
    okp_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_OKP_spec(&okp_keyspec, err);

import_OKP_cleanup:
    cjose_get_dealloc()(x_buffer);
    // d is the private key -> wipe the decoded copy before release
    _cjose_cleanse_dealloc(d_buffer, d_buflen);

    return jwk;
}

cjose_jwk_t *cjose_jwk_import(const char *jwk_str, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    // check params
    if ((NULL == jwk_str) || (0 == len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // parse json content from the given string
    json_t *jwk_json = json_loadb(jwk_str, len, 0, NULL);
    if (NULL == jwk_json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    }

    jwk = cjose_jwk_import_json((cjose_header_t *)jwk_json, err);

// poor man's "finally"
import_cleanup:
    if (NULL != jwk_json)
    {
        json_decref(jwk_json);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import_json(cjose_header_t *json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    json_t *jwk_json = (json_t *)json;

    if (NULL == jwk_json || JSON_OBJECT != json_typeof(jwk_json))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get the string value of the kty attribute of the jwk
    const char *kty_str = _cjose_jwk_get_json_object_string_attribute(jwk_json, CJOSE_JWK_KTY_STR, err);
    if (NULL == kty_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get kty corresponding to kty_str (kty is required)
    cjose_jwk_kty_t kty;
    if (!_cjose_jwk_kty_from_name(kty_str, &kty, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // create a cjose_jwt_t based on the kty
    switch (kty)
    {
    case CJOSE_JWK_KTY_EC:
        jwk = _cjose_jwk_import_EC(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_RSA:
        jwk = _cjose_jwk_import_RSA(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_OCT:
        jwk = _cjose_jwk_import_oct(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_OKP:
        jwk = _cjose_jwk_import_OKP(jwk_json, err);
        break;

    default:
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == jwk)
    {
        // helper function will have already set err
        return NULL;
    }

    // get the value of the kid attribute (kid is optional)
    const char *kid_str = _cjose_jwk_get_json_object_string_attribute(jwk_json, CJOSE_JWK_KID_STR, err);
    if (kid_str != NULL)
    {
        jwk->kid = _cjose_strndup(kid_str, -1, err);
        if (!jwk->kid)
        {
            cjose_jwk_release(jwk);
            return NULL;
        }
    }

    return jwk;
}

//////////////// ECDH ////////////////
// internal data & functions -- ECDH derivation

// ECDH-ES key agreement runs on EC keys and on the OKP X25519 and X448 keys
// (RFC 8037 section 3.2); the Ed25519 and Ed448 signature keys do not qualify
bool _cjose_jwk_is_ecdh_key(const cjose_jwk_t *jwk)
{
    if (NULL == jwk || NULL == jwk->keydata)
    {
        return false;
    }
    if (CJOSE_JWK_KTY_EC == jwk->kty)
    {
        return true;
    }
    if (CJOSE_JWK_KTY_OKP == jwk->kty)
    {
        const cjose_jwk_okp_curve crv = ((okp_keydata *)jwk->keydata)->crv;
        return CJOSE_JWK_OKP_X25519 == crv || CJOSE_JWK_OKP_X448 == crv;
    }
    return false;
}

// whether two keys can perform ECDH-ES with each other: the same key type on
// the same curve
bool _cjose_jwk_ecdh_curve_match(const cjose_jwk_t *a, const cjose_jwk_t *b)
{
    if (!_cjose_jwk_is_ecdh_key(a) || !_cjose_jwk_is_ecdh_key(b) || a->kty != b->kty)
    {
        return false;
    }
    if (CJOSE_JWK_KTY_EC == a->kty)
    {
        return ((ec_keydata *)a->keydata)->crv == ((ec_keydata *)b->keydata)->crv;
    }
    return ((okp_keydata *)a->keydata)->crv == ((okp_keydata *)b->keydata)->crv;
}

bool _cjose_jwk_ecdh_has_private(const cjose_jwk_t *jwk)
{
    if (!_cjose_jwk_is_ecdh_key(jwk))
    {
        return false;
    }
    if (CJOSE_JWK_KTY_EC == jwk->kty)
    {
        return ((ec_keydata *)jwk->keydata)->has_private;
    }
    return ((okp_keydata *)jwk->keydata)->has_private;
}

// a fresh ephemeral key of the type and curve of the given key
cjose_jwk_t *_cjose_jwk_ecdh_ephemeral_key(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!_cjose_jwk_is_ecdh_key(jwk))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (CJOSE_JWK_KTY_EC == jwk->kty)
    {
        return cjose_jwk_create_EC_random(((ec_keydata *)jwk->keydata)->crv, err);
    }
    return cjose_jwk_create_OKP_random(((okp_keydata *)jwk->keydata)->crv, err);
}

// the EVP_PKEY of an ECDH-ES key, with a reference the caller releases
static bool _cjose_jwk_evp_key_for_ecdh(const cjose_jwk_t *jwk, EVP_PKEY **key, cjose_err *err)
{
    if (!_cjose_jwk_is_ecdh_key(jwk) || NULL == key || NULL != *key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    EVP_PKEY *jwk_key = (CJOSE_JWK_KTY_EC == jwk->kty) ? ((ec_keydata *)jwk->keydata)->key : ((okp_keydata *)jwk->keydata)->key;
    if (NULL == jwk_key || 1 != EVP_PKEY_up_ref(jwk_key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    *key = jwk_key;
    return true;
}

cjose_jwk_t *cjose_jwk_derive_ecdh_secret(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    return cjose_jwk_derive_ecdh_ephemeral_key(jwk_self, jwk_peer, salt, salt_len, err);
}

cjose_jwk_t *cjose_jwk_derive_ecdh_ephemeral_key(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    uint8_t *ephemeral_key = NULL;
    size_t ephemeral_key_len = 0;
    cjose_jwk_t *jwk_ephemeral_key = NULL;

    if (!cjose_jwk_derive_ecdh_bits(jwk_self, jwk_peer, &secret, &secret_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // HKDF of the DH shared secret (SHA256, no info, 256 bit expand)
    ephemeral_key_len = 32;
    ephemeral_key = (uint8_t *)cjose_get_alloc()(ephemeral_key_len);
    if (NULL == ephemeral_key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_shared_secret_fail;
    }
    if (!cjose_jwk_hkdf(EVP_sha256(), salt, salt_len, (uint8_t *)"", 0, secret, secret_len, ephemeral_key, ephemeral_key_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // create a JWK of the shared secret
    jwk_ephemeral_key = cjose_jwk_create_oct_spec(ephemeral_key, ephemeral_key_len, err);
    if (NULL == jwk_ephemeral_key)
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // happy path
    _cjose_cleanse_dealloc(secret, secret_len);
    _cjose_cleanse_dealloc(ephemeral_key, ephemeral_key_len);

    return jwk_ephemeral_key;

// fail path
_cjose_jwk_derive_shared_secret_fail:

    if (NULL != jwk_ephemeral_key)
    {
        cjose_jwk_release(jwk_ephemeral_key);
    }
    _cjose_cleanse_dealloc(secret, secret_len);
    _cjose_cleanse_dealloc(ephemeral_key, ephemeral_key_len);
    return NULL;
}

bool cjose_jwk_derive_ecdh_bits(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, uint8_t **output, size_t *output_len, cjose_err *err)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_self = NULL;
    EVP_PKEY *pkey_peer = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;

    // both keys must be of the same type on the same curve
    if (!_cjose_jwk_ecdh_curve_match(jwk_self, jwk_peer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // get EVP_KEY from jwk_self
    if (!_cjose_jwk_evp_key_for_ecdh(jwk_self, &pkey_self, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // get EVP_KEY from jwk_peer
    if (!_cjose_jwk_evp_key_for_ecdh(jwk_peer, &pkey_peer, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // create derivation context based on local key pair
    ctx = EVP_PKEY_CTX_new(pkey_self, NULL);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // initialize derivation context
    if (1 != EVP_PKEY_derive_init(ctx))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // provide the peer public key
    if (1 != EVP_PKEY_derive_set_peer(ctx, pkey_peer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // allocate buffer for shared secret
    secret = (uint8_t *)cjose_get_alloc()(secret_len);
    if (NULL == secret)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_bits_fail;
    }
    memset(secret, 0, secret_len);

    // derive the shared secret
    if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // happy path
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey_self);
    EVP_PKEY_free(pkey_peer);

    *output = secret;
    *output_len = secret_len;
    return true;

_cjose_jwk_derive_bits_fail:

    if (NULL != ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (NULL != pkey_self)
    {
        EVP_PKEY_free(pkey_self);
    }
    if (NULL != pkey_peer)
    {
        EVP_PKEY_free(pkey_peer);
    }
    _cjose_cleanse_dealloc(secret, secret_len);

    return false;
}

bool cjose_jwk_hkdf(const EVP_MD *md,
                    const uint8_t *salt,
                    size_t salt_len,
                    const uint8_t *info,
                    size_t info_len,
                    const uint8_t *ikm,
                    size_t ikm_len,
                    uint8_t *okm,
                    unsigned int okm_len,
                    cjose_err *err)
{
    // current impl. is very limited: SHA256, 256 bit output, and no info
    if ((EVP_sha256() != md) || (0 != info_len) || (32 != okm_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // HKDF-Extract, HMAC-SHA256(salt, IKM) -> PRK
    unsigned int prk_len;
    unsigned char prk[EVP_MAX_MD_SIZE];
    if (NULL == HMAC(md, salt, salt_len, ikm, ikm_len, prk, &prk_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // HKDF-Expand, HMAC-SHA256(PRK,0x01) -> OKM
    const unsigned char t[] = { 0x01 };
    if (NULL == HMAC(md, prk, prk_len, t, sizeof(t), okm, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        _cjose_cleanse(prk, sizeof(prk));
        return false;
    }

    _cjose_cleanse(prk, sizeof(prk));
    return true;
}
