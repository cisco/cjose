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

struct _cjose_jwe_recipient;

// functions for building JWE parts
typedef struct _jwe_rec_fntable_int
{
    bool (*encrypt_ek)(struct _cjose_jwe_recipient *recipient, cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*decrypt_ek)(struct _cjose_jwe_recipient *recipient, cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

} jwe_rec_fntable;

typedef struct _jwe_fntable_int
{

    bool (*set_cek)(cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*set_iv)(cjose_jwe_t *jwe, cjose_err *err);

    bool (*encrypt_dat)(cjose_jwe_t *jwe, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err);

    bool (*decrypt_dat)(cjose_jwe_t *jwe, cjose_err *err);

} jwe_fntable;

struct _cjose_jwe_recipient
{

    json_t *unprotected;                /* unprotected headers */
    struct _cjose_jwe_part_int enc_key; /* encrypted key */
    jwe_rec_fntable fns;                // functions for building JWE parts
};

// JWE object
struct _cjose_jwe_int
{
    json_t *hdr;        // header JSON object
    json_t *shared_hdr; // shared header JSON object

    // struct _cjose_jwe_part_int part[5]; // the 5 compact JWE parts

    struct _cjose_jwe_part_int enc_header;
    struct _cjose_jwe_part_int enc_iv;
    struct _cjose_jwe_part_int enc_ct;
    struct _cjose_jwe_part_int enc_auth_tag;

    jwe_fntable fns;

    uint8_t *cek; // content-encryption key
    size_t cek_len;

    uint8_t *dat; // decrypted data
    size_t dat_len;

    size_t to_count; // recipients count.
    struct _cjose_jwe_recipient *to;
};

#endif // SRC_JWE_INT_H
