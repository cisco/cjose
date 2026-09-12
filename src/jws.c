/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/base64.h>
#include <cjose/header.h>
#include <cjose/jws.h>
#include <cjose/jwk.h>
#include <cjose/util.h>

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include "include/jwk_int.h"
#include "include/header_int.h"
#include "include/jws_int.h"
#include "include/util_int.h"

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_dig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_validate_ec_key(const char *alg, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_dig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_validate_okp_key(const char *alg, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_validate_verify_key(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_hdr(cjose_jws_t *jws, cjose_header_t *header, cjose_err *err)
{
    // save header object as part of the JWS (and incr. refcount)
    jws->hdr = (json_t *)header;
    json_incref(jws->hdr);

    // base64url encode the header
    char *hdr_str = json_dumps(jws->hdr, JSON_ENCODE_ANY | JSON_PRESERVE_ORDER | JSON_COMPACT);
    if (NULL == hdr_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    if (!cjose_base64url_encode((const uint8_t *)hdr_str, strlen(hdr_str), &jws->hdr_b64u, &jws->hdr_b64u_len, err))
    {
        cjose_get_dealloc()(hdr_str);
        return false;
    }
    cjose_get_dealloc()(hdr_str);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_hdr(cjose_jws_t *jws, cjose_err *err)
{
    static const char *const supported_crit_headers[] = { "alg", "cty" };

    if (!_cjose_header_validate_crit((cjose_header_t *)jws->hdr, supported_crit_headers,
                                     sizeof(supported_crit_headers) / sizeof(supported_crit_headers[0]), err))
    {
        return false;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if ((NULL == alg_obj) || (!json_is_string(alg_obj)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    if ((strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_ps;
        jws->fns.verify = _cjose_jws_verify_sig_ps;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_RS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_rs;
        jws->fns.verify = _cjose_jws_verify_sig_rs;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_hmac_sha;
        jws->fns.sign = _cjose_jws_build_sig_hmac_sha;
        jws->fns.verify = _cjose_jws_verify_sig_hmac_sha;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_ec;
        jws->fns.verify = _cjose_jws_verify_sig_ec;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_ED25519) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ED448) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_eddsa;
        jws->fns.sign = _cjose_jws_build_sig_eddsa;
        jws->fns.verify = _cjose_jws_verify_sig_eddsa;
    }
    else
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dat(cjose_jws_t *jws, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err)
{
    // copy plaintext data
    jws->dat_len = plaintext_len;
    jws->dat = (uint8_t *)cjose_get_alloc()(jws->dat_len);
    if ((NULL == jws->dat) && (jws->dat_len > 0))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    memcpy(jws->dat, plaintext, jws->dat_len);

    // base64url encode data
    if (!cjose_base64url_encode((const uint8_t *)plaintext, plaintext_len, &jws->dat_b64u, &jws->dat_b64u_len, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    const EVP_MD *digest_alg = NULL;
    if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0))
        digest_alg = EVP_sha256();
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0))
        digest_alg = EVP_sha384();
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
        digest_alg = EVP_sha512();

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    if (NULL != jws->dig)
    {
        _cjose_cleanse_dealloc(jws->dig, jws->dig_len);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(digest_alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // instantiate and initialize a new mac digest context
    ctx = EVP_MD_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    EVP_MD_CTX_init(ctx);

    // create digest as DIGEST(B64U(HEADER).B64U(DATA))
    if (EVP_DigestInit_ex(ctx, digest_alg, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->hdr_b64u, jws->hdr_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, ".", 1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->dat_b64u, jws->dat_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, jws->dig, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_build_dig_sha_cleanup:
    if (NULL != ctx)
    {
        EVP_MD_CTX_free(ctx);
    }

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;

    // ensure jwk is OCT: only then is keydata the raw key material
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    const EVP_MD *digest_alg = NULL;
    if (strcmp(alg, CJOSE_HDR_ALG_HS256) == 0)
        digest_alg = EVP_sha256();
    else if (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
        digest_alg = EVP_sha384();
    else if (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0)
        digest_alg = EVP_sha512();

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    // RFC 7518 section 3.2: an HMAC key MUST be at least as long as the hash output
    if ((jwk->keysize / 8) < (size_t)EVP_MD_size(digest_alg))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    if (NULL != jws->dig)
    {
        _cjose_cleanse_dealloc(jws->dig, jws->dig_len);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(digest_alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = EVP_MAC_CTX_new(mac);
    if (NULL == mac || NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    OSSL_PARAM params[] = { OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)EVP_MD_get0_name(digest_alg), 0),
                            OSSL_PARAM_END };
    size_t mac_len = 0;
    if (EVP_MAC_init(ctx, jwk->keydata, jwk->keysize / 8, params) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)jws->hdr_b64u, jws->hdr_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)".", 1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)jws->dat_b64u, jws->dat_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_final(ctx, jws->dig, &mac_len, jws->dig_len) != 1 || mac_len != jws->dig_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_build_dig_hmac_sha_cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static const EVP_MD *_cjose_jws_rsa_digest(const char *alg)
{
    if (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0 || strcmp(alg, CJOSE_HDR_ALG_RS256) == 0)
        return EVP_sha256();
    if (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0 || strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
        return EVP_sha384();
    if (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0 || strcmp(alg, CJOSE_HDR_ALG_RS512) == 0)
        return EVP_sha512();
    return NULL;
}

static bool _cjose_jws_rsa_sign(cjose_jws_t *jws, const cjose_jwk_t *jwk, const EVP_MD *digest_alg, int padding, cjose_err *err)
{
    EVP_PKEY *key = _cjose_jwk_rsa_key(jwk);
    EVP_PKEY_CTX *ctx = NULL;

    if (jwk->kty != CJOSE_JWK_KTY_RSA || !_cjose_jwk_rsa_has_private(key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL || EVP_PKEY_sign_init(ctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) != 1
        || EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1
        || (padding == RSA_PKCS1_PSS_PADDING
            && (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest_alg) != 1
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) != 1))
        || EVP_PKEY_sign(ctx, NULL, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    jws->sig = cjose_get_alloc()(jws->sig_len);
    if (jws->sig == NULL)
    {
        EVP_PKEY_CTX_free(ctx);
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    if (EVP_PKEY_sign(ctx, jws->sig, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    if (!cjose_base64url_encode(jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
        return false;
    return true;
}

static bool _cjose_jws_build_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    const EVP_MD *digest_alg = alg_obj == NULL ? NULL : _cjose_jws_rsa_digest(json_string_value(alg_obj));
    if (digest_alg == NULL)
    {
        CJOSE_ERROR(err, alg_obj == NULL ? CJOSE_ERR_INVALID_ARG : CJOSE_ERR_CRYPTO);
        return false;
    }
    return _cjose_jws_rsa_sign(jws, jwk, digest_alg, RSA_PKCS1_PSS_PADDING, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    const EVP_MD *digest_alg = alg_obj == NULL ? NULL : _cjose_jws_rsa_digest(json_string_value(alg_obj));
    if (digest_alg == NULL)
    {
        CJOSE_ERROR(err, alg_obj == NULL ? CJOSE_ERR_INVALID_ARG : CJOSE_ERR_CRYPTO);
        return false;
    }
    return _cjose_jws_rsa_sign(jws, jwk, digest_alg, RSA_PKCS1_PADDING, err);
}

static bool _cjose_jws_build_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    // ensure jwk is OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // allocate buffer for signature
    jws->sig_len = jws->dig_len;
    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    memcpy(jws->sig, jws->dig, jws->sig_len);

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;

    const char *alg = json_string_value(json_object_get(jws->hdr, CJOSE_HDR_ALG));
    if (!_cjose_jws_validate_ec_key(alg, jwk, err))
    {
        return false;
    }

    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    BIGNUM *private_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;
    const EVP_MD *digest_alg = NULL;
    if (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0 || strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0)
        digest_alg = EVP_sha256();
    else if (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)
        digest_alg = EVP_sha384();
    else if (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)
        digest_alg = EVP_sha512();
    if (EVP_PKEY_get_bn_param(keydata->key, OSSL_PKEY_PARAM_PRIV_KEY, &private_key) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    BN_clear_free(private_key);
    ctx = EVP_PKEY_CTX_new(keydata->key, NULL);
    if (digest_alg == NULL || ctx == NULL || EVP_PKEY_sign_init(ctx) != 1
        || EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1
        || EVP_PKEY_sign(ctx, NULL, &der_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }
    der = cjose_get_alloc()(der_len);
    if (der == NULL || EVP_PKEY_sign(ctx, der, &der_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, der == NULL ? CJOSE_ERR_NO_MEMORY : CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }
    const unsigned char *der_pos = der;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_pos, der_len);
    if (NULL == ecdsa_sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    // allocate buffer for signature
    switch (keydata->crv)
    {
    case CJOSE_JWK_EC_P_256:
        jws->sig_len = 32 * 2;
        break;
    case CJOSE_JWK_EC_SECP_256K1:
        jws->sig_len = 32 * 2;
        break;
    case CJOSE_JWK_EC_P_384:
        jws->sig_len = 48 * 2;
        break;
    case CJOSE_JWK_EC_P_521:
        jws->sig_len = 66 * 2;
        break;
    case CJOSE_JWK_EC_INVALID:
        jws->sig_len = 0;
        break;
    }

    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    memset(jws->sig, 0, jws->sig_len);

    const BIGNUM *pr, *ps;
    ECDSA_SIG_get0(ecdsa_sig, &pr, &ps);

    int rlen = BN_num_bytes(pr);
    int slen = BN_num_bytes(ps);
    BN_bn2bin(pr, jws->sig + jws->sig_len / 2 - rlen);
    BN_bn2bin(ps, jws->sig + jws->sig_len - slen);

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    retval = true;

_cjose_jws_build_sig_ec_cleanup:
    EVP_PKEY_CTX_free(ctx);
    cjose_get_dealloc()(der);
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_cser(cjose_jws_t *jws, cjose_err *err)
{
    // both sign and import should be setting these - but check just in case
    if (NULL == jws->hdr_b64u || NULL == jws->dat_b64u || NULL == jws->sig_b64u)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
        return false;
    }

    // compute length of compact serialization
    jws->cser_len = jws->hdr_b64u_len + jws->dat_b64u_len + jws->sig_b64u_len + 3;

    if (NULL != jws->cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
        return false;
    }

    // allocate buffer for compact serialization
    jws->cser = (char *)cjose_get_alloc()(jws->cser_len);
    if (NULL == jws->cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    // build the compact serialization
    snprintf(jws->cser, jws->cser_len, "%s.%s.%s", jws->hdr_b64u, jws->dat_b64u, jws->sig_b64u);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_sign(
    const cjose_jwk_t *jwk, cjose_header_t *protected_header, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err)
{
    cjose_jws_t *jws = NULL;

    if (NULL == jwk || NULL == protected_header || NULL == plaintext)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize JWS
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // build JWS header
    if (!_cjose_jws_build_hdr(jws, protected_header, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build the JWS data segment
    if (!_cjose_jws_build_dat(jws, plaintext, plaintext_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS digest (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // sign the JWS digest
    if (!jws->fns.sign(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS compact serialization
    if (!_cjose_jws_build_cser(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}

////////////////////////////////////////////////////////////////////////////////
void cjose_jws_release(cjose_jws_t *jws)
{
    if (NULL == jws)
    {
        return;
    }

    if (NULL != jws->hdr)
    {
        json_decref(jws->hdr);
    }

    cjose_get_dealloc()(jws->hdr_b64u);
    // the payload may be sensitive: wipe it and the copies that embed it,
    // like the decrypted plaintext of a JWE
    _cjose_cleanse_dealloc(jws->dat, jws->dat_len);
    _cjose_cleanse_dealloc(jws->dat_b64u, jws->dat_b64u_len);
    _cjose_cleanse_dealloc(jws->dig, jws->dig_len);
    _cjose_cleanse_dealloc(jws->sig, jws->sig_len);
    cjose_get_dealloc()(jws->sig_b64u);
    _cjose_cleanse_dealloc(jws->cser, jws->cser_len);
    cjose_get_dealloc()(jws);
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_export(cjose_jws_t *jws, const char **compact, cjose_err *err)
{
    if (NULL == jws || NULL == compact)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (NULL == jws->cser)
    {
        if (!_cjose_jws_build_cser(jws, err))
        {
            return false;
        }
    }

    *compact = jws->cser;
    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_strcpy(char **dst, const char *src, size_t len, cjose_err *err)
{
    *dst = (char *)cjose_get_alloc()(len + 1);
    if (NULL == *dst)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    strncpy(*dst, src, len);
    (*dst)[len] = 0;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_import(const char *cser, size_t cser_len, cjose_err *err)
{
    cjose_jws_t *jws = NULL;
    size_t len = 0;

    if (NULL == cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize a new JWS object
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // find the indexes of the dots; use size_t to match cser_len, an int
    // would truncate the offsets for an oversized serialization
    size_t idx = 0;
    size_t d[2] = { 0, 0 };
    for (size_t i = 0; i < cser_len && idx < 2; ++i)
    {
        if (cser[i] == '.')
        {
            d[idx++] = i;
        }
    }

    // fail if we didn't find both dots
    if (0 == d[1])
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and decode header b64u segment
    uint8_t *hdr_str = NULL;
    jws->hdr_b64u_len = d[0];
    if (!_cjose_jws_strcpy(&jws->hdr_b64u, cser, jws->hdr_b64u_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }
    if (!cjose_base64url_decode(jws->hdr_b64u, jws->hdr_b64u_len, &hdr_str, &len, err) || NULL == hdr_str)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // deserialize JSON header
    jws->hdr = json_loadb((const char *)hdr_str, len, 0, NULL);
    cjose_get_dealloc()(hdr_str);
    if (NULL == jws->hdr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // validate the JSON header segment
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        // make an exception for alg=none so that it will import/parse but not sign/verify
        json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
        if (NULL == alg_obj)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            cjose_jws_release(jws);
            return NULL;
        }
        const char *alg = json_string_value(alg_obj);
        if ((!alg) || (strcmp(alg, CJOSE_HDR_ALG_NONE) != 0))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            cjose_jws_release(jws);
            return NULL;
        }

        // alg=none is accepted (parse-only): clear the validation error
        // recorded above so a successful import does not leave err populated
        CJOSE_ERROR(err, CJOSE_ERR_NONE);
    }

    // copy and b64u decode data segment
    jws->dat_b64u_len = d[1] - d[0] - 1;
    if (!_cjose_jws_strcpy(&jws->dat_b64u, cser + d[0] + 1, jws->dat_b64u_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }
    if (!cjose_base64url_decode(jws->dat_b64u, jws->dat_b64u_len, &jws->dat, &jws->dat_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and b64u decode signature segment
    jws->sig_b64u_len = cser_len - d[1] - 1;
    if (!_cjose_jws_strcpy(&jws->sig_b64u, cser + d[1] + 1, jws->sig_b64u_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }
    if (!cjose_base64url_decode(jws->sig_b64u, jws->sig_b64u_len, &jws->sig, &jws->sig_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *em = NULL;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    const EVP_MD *digest_alg = NULL;
    if (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
        digest_alg = EVP_sha256();
    else if (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
        digest_alg = EVP_sha384();
    else if (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
        digest_alg = EVP_sha512();

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }

    EVP_PKEY *key = _cjose_jwk_rsa_key(jwk);
    if (jws->sig_len != (size_t)EVP_PKEY_get_size(key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }
    em = cjose_get_alloc()(jws->sig_len);
    if (em == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }
    if (!_cjose_jwk_rsa_has_public(key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL || EVP_PKEY_verify_init(ctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1
        || EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest_alg) != 1
        || EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) != 1
        || EVP_PKEY_verify(ctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_ps_cleanup:
    EVP_PKEY_CTX_free(ctx);
    _cjose_cleanse_dealloc(em, jws->sig_len);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_PKEY_CTX *ctx = NULL;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_rs_cleanup;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    const EVP_MD *digest_alg = _cjose_jws_rsa_digest(alg);
    if (digest_alg == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rs_cleanup;
    }

    EVP_PKEY *key = _cjose_jwk_rsa_key(jwk);
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!_cjose_jwk_rsa_has_public(key) || ctx == NULL || EVP_PKEY_verify_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1
        || EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1
        || EVP_PKEY_verify(ctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rs_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_rs_cleanup:
    EVP_PKEY_CTX_free(ctx);
    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    int diff = 0;

    // ensure jwk is OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_hmac_sha_cleanup;
    }

    // verify decrypted digest matches computed digest
    diff |= (jws->sig_len != jws->dig_len);
    if (jws->sig_len == jws->dig_len)
    {
        diff |= cjose_const_memcmp(jws->dig, jws->sig, jws->dig_len);
    }
    if (diff != 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_hmac_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_hmac_sha_cleanup:

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;

    // ensure jwk is EC
    if (jwk->kty != CJOSE_JWK_KTY_EC)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *der = NULL;

    // the JWS ECDSA signature is the fixed-length concatenation R || S, each
    // the curve's coordinate size (RFC 7518 section 3.4); reject any other
    // length before splitting it so a non-canonical signature (e.g. a trailing
    // byte dropped by the sig_len/2 split) cannot verify
    size_t coordlen = 0;
    switch (keydata->crv)
    {
    case CJOSE_JWK_EC_P_256:
        coordlen = 32;
        break;
    case CJOSE_JWK_EC_SECP_256K1:
        coordlen = 32;
        break;
    case CJOSE_JWK_EC_P_384:
        coordlen = 48;
        break;
    case CJOSE_JWK_EC_P_521:
        coordlen = 66;
        break;
    case CJOSE_JWK_EC_INVALID:
        coordlen = 0;
        break;
    }
    if (0 == coordlen || jws->sig_len != coordlen * 2)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }
    int key_len = jws->sig_len / 2;

    BIGNUM *pr = BN_new();
    BIGNUM *ps = BN_new();
    if (pr == NULL || ps == NULL)
    {
        BN_free(pr);
        BN_free(ps);
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }
    BN_bin2bn(jws->sig, key_len, pr);
    BN_bin2bn(jws->sig + key_len, key_len, ps);
    ECDSA_SIG_set0(ecdsa_sig, pr, ps); // takes ownership of pr and ps

    int der_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    if (der_len <= 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }
    der = cjose_get_alloc()((size_t)der_len);
    unsigned char *der_pos = der;
    const char *alg = json_string_value(json_object_get(jws->hdr, CJOSE_HDR_ALG));
    const EVP_MD *digest_alg = NULL;
    if (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0 || strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0)
        digest_alg = EVP_sha256();
    else if (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)
        digest_alg = EVP_sha384();
    else if (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)
        digest_alg = EVP_sha512();
    ctx = EVP_PKEY_CTX_new(keydata->key, NULL);
    if (der == NULL || digest_alg == NULL || i2d_ECDSA_SIG(ecdsa_sig, &der_pos) != der_len || ctx == NULL
        || EVP_PKEY_verify_init(ctx) != 1 || EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1
        || EVP_PKEY_verify(ctx, der, der_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_ec_cleanup:
    EVP_PKEY_CTX_free(ctx);
    cjose_get_dealloc()(der);
    if (ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_ec_key(const char *alg, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (jwk->kty != CJOSE_JWK_KTY_EC)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    ec_keydata *keydata = (ec_keydata *)jwk->keydata;

    // RFC 8812 requires secp256k1 keys to be used only with ES256K and
    // requires ES256K to use a secp256k1 key.
    if ((strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0) != (keydata->crv == CJOSE_JWK_EC_SECP_256K1))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// the fixed size of an EdDSA signature (RFC 8032 sections 5.1.6 and 5.2.6)
static size_t _cjose_jws_eddsa_sig_len(cjose_jwk_okp_curve crv)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return 64;
    case CJOSE_JWK_OKP_ED448:
        return 114;
    default:
        return 0;
    }
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_okp_key(const char *alg, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (jwk->kty != CJOSE_JWK_KTY_OKP)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    okp_keydata *keydata = (okp_keydata *)jwk->keydata;

    // RFC 9864 binds the fully-specified Ed25519 and Ed448 identifiers to a key
    // of that curve, and an X25519/X448 key agreement key never signs (RFC 8037
    // section 3.1); the polymorphic "EdDSA" identifier of RFC 8037, which RFC
    // 9864 deprecates, is not supported
    bool valid = false;
    if (strcmp(alg, CJOSE_HDR_ALG_ED25519) == 0)
    {
        valid = (keydata->crv == CJOSE_JWK_OKP_ED25519);
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_ED448) == 0)
    {
        valid = (keydata->crv == CJOSE_JWK_OKP_ED448);
    }

    if (!valid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    // PureEdDSA (RFC 8037 section 3.1) signs the message itself without a
    // pre-hash, and OpenSSL only offers the one-shot EVP_DigestSign and
    // EVP_DigestVerify for it: the "digest" is the JWS signing input
    // B64U(HEADER).B64U(DATA) (RFC 7515 section 5.1)
    if (NULL != jws->dig)
    {
        _cjose_cleanse_dealloc(jws->dig, jws->dig_len);
        jws->dig = NULL;
    }

    // guard the length of the signing input (+ '.' separator) against size_t overflow
    if (jws->dat_b64u_len > SIZE_MAX - 1 || jws->hdr_b64u_len > SIZE_MAX - 1 - jws->dat_b64u_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    jws->dig_len = jws->hdr_b64u_len + 1 + jws->dat_b64u_len;
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    memcpy(jws->dig, jws->hdr_b64u, jws->hdr_b64u_len);
    jws->dig[jws->hdr_b64u_len] = '.';
    memcpy(jws->dig + jws->hdr_b64u_len + 1, jws->dat_b64u, jws->dat_b64u_len);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;
    size_t sig_len = 0;

    const char *alg = json_string_value(json_object_get(jws->hdr, CJOSE_HDR_ALG));
    if (!_cjose_jws_validate_okp_key(alg, jwk, err))
    {
        return false;
    }

    okp_keydata *keydata = (okp_keydata *)jwk->keydata;

    // OpenSSL 3.0.0 through 3.0.7 sign with the missing private key of a
    // public-only key instead of failing (3.0.8 added the guard), so refuse it
    // here rather than rely on OpenSSL. Copy the private key into a scratch
    // buffer, which is wiped immediately afterward, to detect that condition.
    size_t priv_len = 0;
    if (1 != EVP_PKEY_get_raw_private_key(keydata->key, NULL, &priv_len) || 0 == priv_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    uint8_t *priv = (uint8_t *)cjose_get_alloc()(priv_len);
    if (NULL == priv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    int has_priv = EVP_PKEY_get_raw_private_key(keydata->key, priv, &priv_len);
    _cjose_cleanse_dealloc(priv, priv_len);
    if (1 != has_priv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    // PureEdDSA takes no digest algorithm
    if (1 != EVP_DigestSignInit(ctx, NULL, NULL, NULL, keydata->key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    // allocate buffer for signature: the fixed size of the curve
    jws->sig_len = _cjose_jws_eddsa_sig_len(keydata->crv);
    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    // sign the signing input in one shot
    sig_len = jws->sig_len;
    if (1 != EVP_DigestSign(ctx, jws->sig, &sig_len, jws->dig, jws->dig_len) || sig_len != jws->sig_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    // base64url encode the signature
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_build_sig_eddsa_cleanup:
    EVP_MD_CTX_free(ctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;

    const char *alg = json_string_value(json_object_get(jws->hdr, CJOSE_HDR_ALG));
    if (!_cjose_jws_validate_okp_key(alg, jwk, err))
    {
        return false;
    }

    okp_keydata *keydata = (okp_keydata *)jwk->keydata;

    // the signature has the fixed size of the curve; reject any other length
    // before handing it to OpenSSL
    if (jws->sig_len != _cjose_jws_eddsa_sig_len(keydata->crv))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_eddsa_cleanup;
    }

    // PureEdDSA takes no digest algorithm
    if (1 != EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, keydata->key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_eddsa_cleanup;
    }

    // verify the signature over the signing input in one shot
    if (1 != EVP_DigestVerify(ctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_eddsa_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_eddsa_cleanup:
    EVP_MD_CTX_free(ctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_verify_key(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj || !json_is_string(alg_obj))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    const char *alg = json_string_value(alg_obj);
    if (0 == strcmp(alg, CJOSE_HDR_ALG_NONE))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (((0 == strcmp(alg, CJOSE_HDR_ALG_PS256)) || (0 == strcmp(alg, CJOSE_HDR_ALG_PS384))
         || (0 == strcmp(alg, CJOSE_HDR_ALG_PS512)) || (0 == strcmp(alg, CJOSE_HDR_ALG_RS256))
         || (0 == strcmp(alg, CJOSE_HDR_ALG_RS384)) || (0 == strcmp(alg, CJOSE_HDR_ALG_RS512)))
        && jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (((0 == strcmp(alg, CJOSE_HDR_ALG_HS256)) || (0 == strcmp(alg, CJOSE_HDR_ALG_HS384))
         || (0 == strcmp(alg, CJOSE_HDR_ALG_HS512)))
        && jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if ((0 == strcmp(alg, CJOSE_HDR_ALG_ES256)) || (0 == strcmp(alg, CJOSE_HDR_ALG_ES256K))
        || (0 == strcmp(alg, CJOSE_HDR_ALG_ES384)) || (0 == strcmp(alg, CJOSE_HDR_ALG_ES512)))
    {
        if (!_cjose_jws_validate_ec_key(alg, jwk, err))
        {
            return false;
        }
    }

    if ((0 == strcmp(alg, CJOSE_HDR_ALG_ED25519)) || (0 == strcmp(alg, CJOSE_HDR_ALG_ED448)))
    {
        if (!_cjose_jws_validate_okp_key(alg, jwk, err))
        {
            return false;
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_verify(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jws || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        return false;
    }

    if (!_cjose_jws_validate_verify_key(jws, jwk, err))
    {
        return false;
    }

    // build JWS digest from header and payload (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        return false;
    }

    // verify JWS signature
    if (!jws->fns.verify(jws, jwk, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_get_plaintext(const cjose_jws_t *jws, uint8_t **plaintext, size_t *plaintext_len, cjose_err *err)
{
    if (NULL == jws || NULL == plaintext || NULL == jws->dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    *plaintext = jws->dat;
    *plaintext_len = jws->dat_len;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_jws_get_protected(cjose_jws_t *jws)
{
    if (NULL == jws)
    {
        return NULL;
    }

    return (cjose_header_t *)jws->hdr;
}
