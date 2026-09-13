/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SRC_JWE_INT_H
#define SRC_JWE_INT_H

#include <limits.h>

#include <jansson.h>
#include "cjose/jwe.h"

// JWE part
typedef struct _cjose_jwe_part_int
{
    uint8_t *raw;
    size_t raw_len;

    char *b64u;
    size_t b64u_len;
} _jwe_part_t;

typedef struct _cjose_jwe_recipient _jwe_int_recipient_t;

// functions for building JWE parts
typedef struct _jwe_rec_fntable_int
{
    bool (*encrypt_ek)(_jwe_int_recipient_t *recipient, cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

    bool (*decrypt_ek)(_jwe_int_recipient_t *recipient, cjose_jwe_t *jwe, const cjose_jwk_t *jwk, cjose_err *err);

} jwe_rec_fntable;

typedef struct _jwe_fntable_int
{

    bool (*set_cek)(cjose_jwe_t *jwe, const cjose_jwk_t *jwk, bool random, cjose_err *err);

    bool (*set_iv)(cjose_jwe_t *jwe, cjose_err *err);

    bool (*encrypt_dat)(cjose_jwe_t *jwe, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err);

    bool (*decrypt_dat)(cjose_jwe_t *jwe, cjose_err *err);

} jwe_fntable;

struct _cjose_jwe_recipient
{

    json_t *unprotected; /* unprotected headers */
    _jwe_part_t enc_key; /* encrypted key */
    jwe_rec_fntable fns; // functions for building JWE parts
};

// JWE object
struct _cjose_jwe_int
{
    json_t *hdr;        // header JSON object
    json_t *shared_hdr; // shared header JSON object

    // _jwe_part_t part[5]; // the 5 compact JWE parts

    _jwe_part_t enc_header;
    _jwe_part_t enc_iv;
    _jwe_part_t enc_ct;
    _jwe_part_t enc_auth_tag;

    jwe_fntable fns;

    uint8_t *cek; // content-encryption key
    size_t cek_len;

    uint8_t *dat; // decrypted data
    size_t dat_len;

    size_t to_count; // recipients count.
    _jwe_int_recipient_t *to;
};

// PBES2 (RFC 7518 section 4.8) parameter bounds. Of these only the minimum
// salt input length is an RFC requirement: section 4.8.1.1 makes 8 octets a
// MUST. The rest is cjose policy, not validation the RFC asks for, and every
// #ifndef'd value below can be set at build time, through the CMake variable
// of the same name or by defining it for the whole build, since the test
// suite asserts against the same constants. The defaults are the values below,
// and the iteration counts must keep the order the second _Static_assert names:
//
//   - the count cjose will produce at its lowest, the RFC's recommendation by
//     default. RFC 7518 section 4.8.1.2 requires a positive count and
//     RECOMMENDS at least 1000, so cjose refuses to write a JWE below what this
//     names. It is a producer policy: it does not bound what cjose reads.
//   - the count cjose will accept at its lowest, which is the RFC's "positive"
//     and nothing more, so that a conformant producer's JWE is readable
//     whatever count it chose. Refusing to read a weak count does not make the
//     JWE stronger, and the count is the producer's to pick; a deployment that
//     would rather fail closed on one raises this.
//   - the count cjose will neither write nor accept above. The RFC sets none,
//     but on decrypt the count is attacker-controlled, and with several
//     recipients it sits in an unprotected header, so nothing but this bounds
//     the PBKDF2 work an unauthenticated JWE can demand. Note that the bound is
//     per recipient: cjose_jwe_decrypt_multi derives a key for every recipient
//     the locator matches. Keep it at or above 100000, the highest default a
//     mainstream producer ships, or cjose will refuse that producer's output.
//   - the salt ceiling. Again none in the RFC; this keeps the salt input the
//     length of an identifier rather than of a payload.
//   - the count used when the caller sets no "p2c". Several widely used
//     implementations refuse tokens above roughly 10000 to 16384 iterations by
//     default, so a higher value would produce JWEs they cannot read.
//
// The salt input itself is not a knob: it is always generated here, 16 octets
// from the RNG, because RFC 7518 section 4.8.1.1 requires a new random one for
// every encryption operation. A caller-supplied "p2s" is refused rather than
// quietly dropped.
#define CJOSE_JWE_PBES2_SALT_LEN 16
#define CJOSE_JWE_PBES2_MIN_SALT_LEN 8
#ifndef CJOSE_JWE_PBES2_MAX_SALT_LEN
#define CJOSE_JWE_PBES2_MAX_SALT_LEN 1024
#endif
#ifndef CJOSE_JWE_PBES2_MIN_ITERATIONS
#define CJOSE_JWE_PBES2_MIN_ITERATIONS 1000
#endif
#ifndef CJOSE_JWE_PBES2_MIN_ACCEPTED_ITERATIONS
#define CJOSE_JWE_PBES2_MIN_ACCEPTED_ITERATIONS 1
#endif
#ifndef CJOSE_JWE_PBES2_MAX_ITERATIONS
#define CJOSE_JWE_PBES2_MAX_ITERATIONS 1000000
#endif
#ifndef CJOSE_JWE_PBES2_DEFAULT_ITERATIONS
#define CJOSE_JWE_PBES2_DEFAULT_ITERATIONS 8192
#endif

_Static_assert(CJOSE_JWE_PBES2_MIN_SALT_LEN <= CJOSE_JWE_PBES2_SALT_LEN && CJOSE_JWE_PBES2_SALT_LEN <= CJOSE_JWE_PBES2_MAX_SALT_LEN
                   && CJOSE_JWE_PBES2_MAX_SALT_LEN <= INT_MAX,
               "the generated PBES2 salt input must be within the accepted bounds, which PKCS5_PBKDF2_HMAC takes as an int");
// what cjose produces it must also accept, so the accepted range contains the
// produced one; RFC 7518 section 4.8.1.2 makes a count of zero or less invalid
_Static_assert(CJOSE_JWE_PBES2_MIN_ACCEPTED_ITERATIONS >= 1
                   && CJOSE_JWE_PBES2_MIN_ACCEPTED_ITERATIONS <= CJOSE_JWE_PBES2_MIN_ITERATIONS
                   && CJOSE_JWE_PBES2_MIN_ITERATIONS <= CJOSE_JWE_PBES2_DEFAULT_ITERATIONS
                   && CJOSE_JWE_PBES2_DEFAULT_ITERATIONS <= CJOSE_JWE_PBES2_MAX_ITERATIONS
                   && CJOSE_JWE_PBES2_MAX_ITERATIONS <= INT_MAX,
               "the PBES2 iteration counts must be positive, ordered accepted <= produced <= default <= maximum, and fit an int");

#endif // SRC_JWE_INT_H
