/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/jwk.h>

#include <jansson.h>

#include <openssl/evp.h>

#ifndef SRC_JWK_INT_H
#define SRC_JWK_INT_H

// key-specific function table
typedef struct _key_fntable_int
{
    void (*free_func)(cjose_jwk_t *);
    bool (*public_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
    bool (*private_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
} key_fntable;

// JSON Web Key structure
struct _cjose_jwk_int
{
    cjose_jwk_kty_t kty;
    char *kid;
    unsigned int retained;
    size_t keysize;
    void *keydata;
    const key_fntable *fns;
};

// EC-specific keydata
typedef struct _ec_keydata_int
{
    cjose_jwk_ec_curve crv;
    EVP_PKEY *key;
    bool has_private;
} ec_keydata;

// OKP-specific keydata (RFC 8037): the EVP_PKEY holds the raw Ed25519,
// Ed448, X25519 or X448 key
typedef struct _okp_keydata_int
{
    cjose_jwk_okp_curve crv;
    EVP_PKEY *key;
    bool has_private;
} okp_keydata;

typedef struct _rsa_keydata_int
{
    EVP_PKEY *key;
    bool has_private;
    bool has_factors;
    bool has_crt;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dp;
    BIGNUM *dq;
    BIGNUM *qi;
} rsa_keydata;

static inline EVP_PKEY *_cjose_jwk_rsa_key(const cjose_jwk_t *jwk) { return ((rsa_keydata *)jwk->keydata)->key; }

bool _cjose_jwk_rsa_has_private(const cjose_jwk_t *jwk);

// ECDH-ES runs on EC keys and on OKP X25519 and X448 keys (RFC 8037 section 3.2)
bool _cjose_jwk_is_ecdh_key(const cjose_jwk_t *jwk);
bool _cjose_jwk_ecdh_curve_match(const cjose_jwk_t *a, const cjose_jwk_t *b);
cjose_jwk_t *_cjose_jwk_ecdh_ephemeral_key(const cjose_jwk_t *jwk, cjose_err *err);

bool cjose_jwk_derive_ecdh_bits(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, uint8_t **output, size_t *output_len, cjose_err *err);

// HKDF implementation, note it currrently supports only SHA256, no info
// and okm must be exactly 32 bytes.
bool cjose_jwk_hkdf(const EVP_MD *md,
                    const uint8_t *salt,
                    size_t salt_len,
                    const uint8_t *info,
                    size_t info_len,
                    const uint8_t *ikm,
                    size_t ikm_len,
                    uint8_t *okm,
                    unsigned int okm_len,
                    cjose_err *err);

#endif // SRC_JWK_INT_H
