/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SRC_JWE_INT_H
#define SRC_JWE_INT_H

#include <jansson.h>
#include "cjose/jwe.h"

// JWE part
struct _cjose_jwe_part_int
{
    uint8_t *raw;
    size_t raw_len;

    char *b64u;
    size_t b64u_len;
};

// functions for building JWE parts
typedef struct _jwe_fntable_int
{
    bool (*set_cek)(cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*encrypt_ek)(cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*decrypt_ek)(cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*set_iv)(cjose_jwe_t *jwe, cjose_err *err);

    bool (*encrypt_dat)(cjose_jwe_t *jwe, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err);

    bool (*decrypt_dat)(cjose_jwe_t *jwe, cjose_err *err);

} jwe_fntable;

// JWE object
struct _cjose_jwe_int
{
    json_t *hdr; // header JSON object

    struct _cjose_jwe_part_int part[5]; // the 5 JWE parts

    uint8_t *cek; // content-encryption key
    size_t cek_len;

    uint8_t *dat; // decrypted data
    size_t dat_len;

    jwe_fntable fns; // functions for building JWE parts
};

#endif // SRC_JWE_INT_H
