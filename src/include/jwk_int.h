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

// RFC 9964 section 7.3: the seed is 256 bits for every ML-DSA algorithm, and
// the length check is a MUST
#define CJOSE_JWK_AKP_SEED_LEN 32

// AKP-specific keydata (RFC 9964): the EVP_PKEY holds the ML-DSA key, built
// from the 32 octet seed for a private key and from the public key otherwise.
// The seed is kept beside it because RFC 9964 section 4 puts it in "priv" and
// an OpenSSL configured with ml-dsa.retain_seed=no will not give it back, so a
// key would otherwise be unable to survive its own export; this is why
// rsa_keydata keeps its BIGNUMs too. It is wiped with the key.
typedef struct _akp_keydata_int
{
    cjose_jwk_akp_alg alg;
    EVP_PKEY *key;
    bool has_private;
    uint8_t seed[CJOSE_JWK_AKP_SEED_LEN];
} akp_keydata;

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

#ifdef HAVE_ML_DSA
// the RFC 9964 name of an AKP algorithm, which is both the JWK "alg" value and
// the name OpenSSL fetches the implementation by, and the reverse mapping
const char *_cjose_jwk_akp_name_for_alg(cjose_jwk_akp_alg alg);
bool _cjose_jwk_akp_alg_from_name(const char *name, cjose_jwk_akp_alg *alg);
#endif // HAVE_ML_DSA

// ECDH-ES runs on EC keys and on OKP X25519 and X448 keys (RFC 8037 section 3.2)
bool _cjose_jwk_is_ecdh_key(const cjose_jwk_t *jwk);
bool _cjose_jwk_ecdh_curve_match(const cjose_jwk_t *a, const cjose_jwk_t *b);
// true when an EC or OKP key carries its private part; RFC 7518 section 4.6.1.1
// allows only public parameters in the "epk" header
bool _cjose_jwk_ecdh_has_private(const cjose_jwk_t *jwk);
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
                    size_t okm_len,
                    cjose_err *err);

#endif // SRC_JWK_INT_H
