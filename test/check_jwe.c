/*!
 *
 */

#include "check_cjose.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include "include/jwk_int.h"
#include "include/jwe_int.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cjose/error.h>

// a JWK of type RSA
static const char *JWK_RSA
    = "{ \"kty\": \"RSA\", "
      "\"e\": \"AQAB\", "
      "\"n\": "
      "\"wsqJbopx18NQFYLYOq4ZeMSE89yGiEankUpf25yV8QqroKUGrASj_OeqTWUjwPGKTN1vGFFuHYxiJeAUQH2qQPmg9Oqk6-"
      "ATBEKn9COKYniQ5459UxCwmZA2RL6ufhrNyq0JF3GfXkjLDBfhU9zJJEOhknsA0L_c-X4AI3d_NbFdMqxNe1V_"
      "UWAlLcbKdwO6iC9fAvwUmDQxgy6R0DC1CMouQpenMRcALaSHar1cm4K-syoNobv3HEuqgZ3s6-hOOSqauqAO0GUozPpaIA7OeruyRl5sTWT0r-"
      "iz39bchID2bIKtcqLiFcSYPLBcxmsaQCqRlGhmv6stjTCLV1yT9w\", "
      "\"kid\": \"ff3c5c96-392e-46ef-a839-6ff16027af78\", "
      "\"d\": "
      "\"b9hXfQ8lOtw8mX1dpqPcoElGhbczz_-xq2znCXQpbBPSZBUddZvchRSH5pSSKPEHlgb3CSGIdpLqsBCv0C_XmCM9ViN8uqsYgDO9uCLIDK5plWttbkqA_"
      "EufvW03R9UgIKWmOL3W4g4t-"
      "C2mBb8aByaGGVNjLnlb6i186uBsPGkvaeLHbQcRQKAvhOUTeNiyiiCbUGJwCm4avMiZrsz1r81Y1Z5izo0ERxdZymxM3FRZ9vjTB-"
      "6DtitvTXXnaAm1JTu6TIpj38u2mnNLkGMbflOpgelMNKBZVxSmfobIbFN8CHVc1UqLK2ElsZ9RCQANgkMHlMkOMj-XT0wHa3VBUQ\", "
      "\"p\": "
      "\"8mgriveKJAp1S7SHqirQAfZafxVuAK_A2QBYPsAUhikfBOvN0HtZjgurPXSJSdgR8KbWV7ZjdJM_eOivIb_XiuAaUdIOXbLRet7t9a_"
      "NJtmX9iybhoa9VOJFMBq_rbnbbte2kq0-FnXmv3cukbC2LaEw3aEcDgyURLCgWFqt7M0\", "
      "\"q\": "
      "\"zbbTv5421GowOfKVEuVoA35CEWgl8mdasnEZac2LWxMwKExikKU5LLacLQlcOt7A6n1ZGUC2wyH8mstO5tV34Eug3fnNrbnxFUEE_ZB_njs_"
      "rtZnwz57AoUXOXVnd194seIZF9PjdzZcuwXwXbrZ2RSVW8if_ZH5OVYEM1EsA9M\", "
      "\"dp\": "
      "\"1BaIYmIKn1X3InGlcSFcNRtSOnaJdFhRpotCqkRssKUx2qBlxs7ln_5dqLtZkx5VM_UE_GE7yzc6BZOwBxtOftdsr8HVh-14ksSR9rAGEsO2zVBiEuW4qZf_"
      "aQM-ScWfU--wcczZ0dT-Ou8P87Bk9K9fjcn0PeaLoz3WTPepzNE\", "
      "\"dq\": "
      "\"kYw2u4_UmWvcXVOeV_VKJ5aQZkJ6_sxTpodRBMPyQmkMHKcW4eKU1mcJju_"
      "deqWadw5jGPPpm5yTXm5UkAwfOeookoWpGa7CvVf4kPNI6Aphn3GBjunJHNpPuU6w-wvomGsxd-NqQDGNYKHuFFMcyXO_zWXglQdP_1o1tJ1M-BM\", "
      "\"qi\": "
      "\"j94Ens784M8zsfwWoJhYq9prcSZOGgNbtFWQZO8HP8pcNM9ls7YA4snTtAS_"
      "B4peWWFAFZ0LSKPCxAvJnrq69ocmEKEk7ss1Jo062f9pLTQ6cnhMjev3IqLocIFt5Vbsg_PWYpFSR7re6FRbF9EYOM7F2-HRv1idxKCWoyQfBqk\" }";

// a JWK of type EC
static const char *JWK_EC = "{ \"kty\": \"EC\", "
                            "\"crv\": \"P-256\", "
                            "\"x\": \"DxaAKzwruXJh4IkdieycIJER6w8M1TYMCV3qOa-l9CM\", "
                            "\"y\": \"_kRI1aD7-PMFwhUpXmcRzw6hALF_xdKwADuKOM-xsak\", "
                            "\"d\":\"SOu5eRc40yn5yVrg069VjWNH4wsoErN8_AxmH4cI88s\" }";

// a JWK of type oct
static const char *JWK_OCT_16 = "{\"kty\":\"oct\", "
                                "\"k\":\"3921VrO5TrLvPQ-NFLlghQ\"}";
static const char *JWK_OCT_24 = "{\"kty\":\"oct\", "
                                "\"k\":\"dC4ZvqLVuS-esAz331EEd8HiwCBM1dih\"}";
static const char *JWK_OCT_32 = "{\"kty\":\"oct\", "
                                "\"k\":\"ZMpktzGq1g6_r4fKVdnx9OaYr4HjxPjIs7l7SwAsgsg\"}";
static const char *JWK_OCT_48 = "{\"kty\":\"oct\", "
                                "\"k\":\"2xAZsjSXMTg6XtY5AESrM3slgXzUaXHFEaGrALThNPyC_9JeO8Hg4PZpLDdhDIlk\"}";
static const char *JWK_OCT_64 = "{\"kty\":\"oct\", "
                                "\"k\":\"Jc2RE4DiwDGZsDTVt0Am3ZI_6IhSuoeQdRaHs_XKl_WnmFkHuvGr8px7h_2rme4rpYGHx93I7jl4p9swfJwlzQ\"}";

// a JWE encrypted with the above JWK_RSA key (using node-jose)
static const char *JWE_RSA
    = "eyJraWQiOiJmZjNjNWM5Ni0zOTJlLTQ2ZWYtYTgzOS02ZmYxNjAyN2FmNzgiLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
      "FGQ9IUhjmSJr4dAntH0DP-dAJiZPfKCRhg-SjUywNFqmG-ruhRvio1K7qy2Z0joatZxdJmkOInlsGvGIZeyapTtOndshCsfTlazHH-4fqFyepIm6o-gZ8gfntDG_"
      "sa9hi9uw1KxeJfNmaL94JMjq-QVmocdCeruIE7_bL90MNflQ8qf5vhuh_hF_Ea_vUnHlIbbQsF1ZF4rRsEGBR7CxTBxusMgErct0kp3La6qQbnX8fDJMqL_"
      "aeot4xZRm3zobIYqKePaGBaSJ7wooWslM1w57IrYXN0UVODRAFO6L5ldF_PHpWbBnFx4k_-FWCOVb-iVpQmLtBkniKG6iItXVUQ.ebcXmjWfUMq-brIT."
      "BPt7F9tcIwQpoAjlyguagOGftJE392-j3kSnP5I6nB-WhWKfpPAeChIW23oWTUHlUbadOeBaiI6r-2TLTZzf3jFKc8Wwr-F0q_iEUQjmg3om-PKR_Pgl_"
      "ncDTXjkxSQjbHOAV1JByh61G-WFuEC1UItyib0AOq9R.Mlo2kQF8Zn2hwwdDl_4Lnw";

// the plaintext payload of the above JWE object(s)
static const char *PLAINTEXT = "If you reveal your secrets to the wind, you should not blame the "
                               "wind for revealing them to the trees. — Kahlil Gibran";

static const cjose_jwk_t *cjose_multi_key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void *data)
{
    const char *kid = cjose_header_get(hdr, CJOSE_HDR_KID, NULL);
    if (NULL != kid)
    {

        ;
        for (cjose_jwe_recipient_t *recs = data; recs->jwk; recs++)
        {
            const char *t_kid = cjose_jwk_get_kid(recs->jwk, NULL);
            if (NULL != t_kid && !strcmp(t_kid, kid))
            {
                return recs->jwk;
            }
        }
    }

    return NULL;
}

START_TEST(test_cjose_jwe_node_jose_encrypt_self_decrypt)
{
    cjose_err err;

    // import the JWK
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the JWE
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain2_len = 0;
    uint8_t *plain2 = cjose_jwe_decrypt(jwe, jwk, &plain2_len, &err);
    ck_assert_msg(NULL != plain2,
                  "cjose_jwe_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // confirm plain2 == PLAINTEXT
    ck_assert_msg(plain2_len == strlen(PLAINTEXT),
                  "length of decrypted plaintext does not match length of original, "
                  "expected: %lu, found: %lu",
                  strlen(PLAINTEXT), plain2_len);
    ck_assert_msg(strncmp(PLAINTEXT, plain2, plain2_len) == 0, "decrypted plaintext does not match encrypted plaintext");

    cjose_get_dealloc()(plain2);
    cjose_jwk_release(jwk);
    cjose_jwe_release(jwe);
}
END_TEST

static void _self_encrypt_self_decrypt_with_key(const char *alg, const char *enc, const char *key, const char *plain1)
{
    cjose_err err;

    cjose_jwk_t *jwk = cjose_jwk_import(key, strlen(key), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // set header for JWE
    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ENC, enc, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // create the JWE
    size_t plain1_len = strlen(plain1);
    cjose_jwe_t *jwe1 = cjose_jwe_encrypt(jwk, hdr, plain1, plain1_len, &err);
    ck_assert_msg(NULL != jwe1, "cjose_jwe_encrypt failed: %s, file: %s, function: %s, line: %ld", err.message, err.file,
                  err.function, err.line);
    // ck_assert(hdr == cjose_jwe_get_protected(jwe1));

    // get the compact serialization of JWE
    char *compact = cjose_jwe_export(jwe1, &err);
    ck_assert_msg(NULL != compact, "cjose_jwe_export failed: %s, file: %s, function: %s, line: %ld", err.message, err.file,
                  err.function, err.line);

    // deserialize the compact representation to a new JWE
    cjose_jwe_t *jwe2 = cjose_jwe_import(compact, strlen(compact), &err);
    ck_assert_msg(NULL != jwe2,
                  "cjose_jwe_import failed for algo %s, method %s: "
                  "%s, file: %s, function: %s, line: %ld",
                  alg, enc, err.message, err.file, err.function, err.line);

    // get the decrypted plaintext
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    plain2 = cjose_jwe_decrypt(jwe2, jwk, &plain2_len, &err);
    ck_assert_msg(NULL != plain2,
                  "cjose_jwe_decrypt failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // confirm plain2 == plain1
    ck_assert(json_equal((json_t *)cjose_jwe_get_protected(jwe1), (json_t *)cjose_jwe_get_protected(jwe2)));
    ck_assert_msg(plain2_len == strlen(plain1),
                  "length of decrypted plaintext does not match length of original, "
                  "expected: %lu, found: %lu",
                  strlen(plain1), plain2_len);
    ck_assert_msg(strncmp(plain1, plain2, plain2_len) == 0, "decrypted plaintext does not match encrypted plaintext");

    cjose_get_dealloc()(plain2);
    cjose_header_release(hdr);
    cjose_jwe_release(jwe1);
    cjose_jwe_release(jwe2);
    cjose_jwk_release(jwk);
    cjose_get_dealloc()(compact);
}

static void _self_encrypt_self_decrypt(const char *plain1)
{
    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_RSA_OAEP, CJOSE_HDR_ENC_A256GCM, JWK_RSA, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_RSA1_5, CJOSE_HDR_ENC_A256GCM, JWK_RSA, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_DIR, CJOSE_HDR_ENC_A256GCM, JWK_OCT_32, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_DIR, CJOSE_HDR_ENC_A128CBC_HS256, JWK_OCT_32, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_DIR, CJOSE_HDR_ENC_A192CBC_HS384, JWK_OCT_48, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_DIR, CJOSE_HDR_ENC_A256CBC_HS512, JWK_OCT_64, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_A128KW, CJOSE_HDR_ENC_A128CBC_HS256, JWK_OCT_16, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_A192KW, CJOSE_HDR_ENC_A192CBC_HS384, JWK_OCT_24, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_A256KW, CJOSE_HDR_ENC_A256CBC_HS512, JWK_OCT_32, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_A128KW, CJOSE_HDR_ENC_A256GCM, JWK_OCT_16, plain1);

    _self_encrypt_self_decrypt_with_key(CJOSE_HDR_ALG_ECDH_ES, CJOSE_HDR_ENC_A256GCM, JWK_EC, plain1);
}

START_TEST(test_cjose_jwe_self_encrypt_self_decrypt)
{
    _self_encrypt_self_decrypt("Sed ut perspiciatis unde omnis iste natus error sit voluptatem "
                               "doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo "
                               "veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo "
                               "ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed "
                               "consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. "
                               "porro quisquam est, qui dolorem ipsum quia dolor sit amet, "
                               "adipisci velit, sed quia non numquam eius modi tempora incidunt ut "
                               "dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, "
                               "nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut "
                               "ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in "
                               "voluptate velit esse quam nihil molestiae consequatur, vel illum qui "
                               "eum fugiat quo voluptas nulla pariatur?");
}
END_TEST

START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_short) { _self_encrypt_self_decrypt("Setec Astronomy"); }
END_TEST

START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_empty) { _self_encrypt_self_decrypt(""); }
END_TEST

START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_large)
{
    // encrypt and decrypt a 4MB buffer of z's
    size_t len = 1024 * 4096;
    char *plain = (char *)malloc(len);
    memset(plain, 'z', len);
    plain[len - 1] = 0;
    // _self_encrypt_self_decrypt(plain);
    free(plain);
}
END_TEST

START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_many)
{
    // encrypt and decrypt a whole lot of randomly sized payloads
    for (int i = 0; i < 100; ++i)
    {
        size_t len = random() % 1024;
        char *plain = (char *)malloc(len);
        ck_assert_msg(RAND_bytes(plain, len) == 1, "RAND_bytes failed");
        plain[len - 1] = 0;
        _self_encrypt_self_decrypt(plain);
        free(plain);
    }
}
END_TEST

START_TEST(test_cjose_jwe_encrypt_with_bad_header)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

    static const char *plain = "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    static const char *JWK
        = "{ \"kty\": \"RSA\", "
          "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
          "\"e\": \"AQAB\", "
          "\"n\": "
          "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
          "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
          "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
          "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // set header for JWE with bad alg
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, "Cayley-Purser", &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // create a JWE
    jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

    // set header for JWE with bad enc
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ENC, "Twofish", &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // create a JWE
    jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwe_encrypt_with_bad_key)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

    static const char *plain = "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // importing private key with a missing public part 'e' fails at cjose_jwk_import

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // set header for JWE
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // attempt encryption with each bad key
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk = cjose_jwk_import(JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk,
                      "cjose_jwk_import failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
        ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad key");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

        cjose_jwk_release(jwk);
    }

    jwe = cjose_jwe_encrypt(NULL, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad key");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

    cjose_header_release(hdr);
}
END_TEST

START_TEST(test_cjose_jwe_encrypt_with_bad_content)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

    static const char *JWK
        = "{ \"kty\": \"RSA\", "
          "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
          "\"e\": \"AQAB\", "
          "\"n\": "
          "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
          "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
          "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
          "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // set header for JWE
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    jwe = cjose_jwe_encrypt(jwk, hdr, NULL, 1024, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

    jwe = cjose_jwe_encrypt(jwk, hdr, NULL, 0, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_encrypt returned bad err.code");

    cjose_jwk_release(jwk);
    cjose_header_release(hdr);
}
END_TEST

START_TEST(test_cjose_jwe_import_export_compare)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the jwe created with the common key
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // re-export the jwe object
    char *cser = cjose_jwe_export(jwe, &err);
    ck_assert_msg(NULL != cser,
                  "re-export of imported JWE failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // compare the re-export to the original serialization
    ck_assert_msg(strncmp(JWE_RSA, cser, strlen(JWE_RSA)) == 0, "export of imported JWE doesn't match original");

    cjose_jwk_release(jwk);
    cjose_jwe_release(jwe);
    cjose_get_dealloc()(cser);
}
END_TEST

START_TEST(test_cjose_jwe_import_invalid_serialization)
{
    cjose_err err;

    static const char *JWE_BAD[]
        = { "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_"
            "Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_"
            "cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w."
            "NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_"
            "E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_"
            "so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_"
            "oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-"
            "K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_"
            "HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-"
            "VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-"
            "1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_"
            "74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_"
            "sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_"
            "UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-"
            "QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_"
            "69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-"
            "GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-"
            "ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-"
            "HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_"
            "WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-"
            "o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg.x",
            "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_"
            "Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_"
            "cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w."
            "NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_"
            "E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_"
            "so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_"
            "oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-"
            "K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_"
            "HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-"
            "VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-"
            "1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_"
            "74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_"
            "sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_"
            "UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-"
            "QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_"
            "69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-"
            "GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-"
            "ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-"
            "HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_"
            "WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-"
            "o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg.",
            "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_"
            "Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_"
            "cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w."
            "NnDIbUkIHi1suUKk..jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_"
            "E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_"
            "so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_"
            "oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-"
            "K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_"
            "HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-"
            "VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-"
            "1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_"
            "74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_"
            "sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_"
            "UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-"
            "QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_"
            "69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-"
            "GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-"
            "ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-"
            "HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_"
            "WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-"
            "o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg",
            ".eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_"
            "Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_"
            "cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w."
            "NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_"
            "E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_"
            "so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_"
            "oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-"
            "K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_"
            "HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-"
            "VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-"
            "1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_"
            "74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_"
            "sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_"
            "UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-"
            "QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_"
            "69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-"
            "GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-"
            "ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-"
            "HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_"
            "WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-"
            "o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg",
            "AAAA.BBBB.CCCC.DDDD",
            "AAAA.BBBB.CCCC",
            "AAAA.BBBB",
            "AAAA",
            "",
            "....",
            "this test is dedicated to swhitsel",
            NULL };

    for (int i = 0; NULL != JWE_BAD[i]; ++i)
    {
        cjose_jwe_t *jwe = cjose_jwe_import(JWE_BAD[i], strlen(JWE_BAD[i]), &err);
        ck_assert_msg(NULL == jwe, "cjose_jwe_import of bad JWE succeeded (%d)", i);
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_import returned wrong err.code");
    }
}
END_TEST

START_TEST(test_cjose_jwe_decrypt_bad_params)
{
    cjose_err err;
    size_t len = 0;

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for encryption
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": "
        "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
        "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
        "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
        "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\" }",

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the jwe created with the common key
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // try to decrypt a NULL jwe
    ck_assert_msg(!cjose_jwe_decrypt(NULL, jwk, &len, &err), "cjose_jwe_decrypt succeeded with NULL jwe");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_decrypt returned wrong err.code");

    // try to decrypt with a NULL jwk
    ck_assert_msg(!cjose_jwe_decrypt(jwe, NULL, &len, &err), "cjose_jwe_decrypt succeeded with NULL jwk");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_decrypt returned wrong err.code");

    // try to decrypt with bad/wrong/unsupported keys
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk_bad = cjose_jwk_import(JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk_bad, "cjose_jwk_import failed");

        ck_assert_msg(!cjose_jwe_decrypt(jwe, NULL, &len, &err), "cjose_jwe_decrypt succeeded with bad jwk");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jwe_decrypt returned wrong err.code");

        cjose_jwk_release(jwk_bad);
    }

    cjose_jwe_release(jwe);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwe_decrypt_aes)
{
    // https://tools.ietf.org/html/rfc7516#appendix-A.3
    // JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
    static const char *JWK_S = "{\"kty\":\"oct\", \"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
    static const char *JWE_S = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
                               "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
                               "AxY8DCtDaGlsbGljb3RoZQ."
                               "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
                               "U0m_YmjN04DJvceFICbCVQ";
    static const char *PLAINTEXT_S = "Live long and prosper.";

    cjose_err err;

    // import the JWK
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_S, strlen(JWK_S), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the JWE
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_S, strlen(JWE_S), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain1_len = 0;
    uint8_t *plain1 = cjose_jwe_decrypt(jwe, jwk, &plain1_len, &err);
    ck_assert_msg(NULL != plain1,
                  "cjose_jwe_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // confirm plain == PLAINTEXT_S
    ck_assert_msg(plain1_len == strlen(PLAINTEXT_S),
                  "length of decrypted plaintext does not match length of original, "
                  "expected: %lu, found: %lu",
                  strlen(PLAINTEXT_S), plain1_len);
    ck_assert_msg(strncmp(PLAINTEXT_S, plain1, plain1_len) == 0, "decrypted plaintext does not match encrypted plaintext");

    cjose_get_dealloc()(plain1);
    cjose_jwe_release(jwe);

    static const char *JWE_TAMPERED_AT = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
                                         "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
                                         "AxY8DCtDaGlsbGljb3RoZQ."
                                         "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
                                         "U0m_YmjN04DJvceFICbCVq";

    // import the JWE
    jwe = cjose_jwe_import(JWE_TAMPERED_AT, strlen(JWE_TAMPERED_AT), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain2_len = 0;
    uint8_t *plain2 = cjose_jwe_decrypt(jwe, jwk, &plain2_len, &err);
    ck_assert_msg(NULL == plain2, "cjose_jwe_get_plaintext succeeded for tampered authentication tag");

    cjose_jwe_release(jwe);

    static const char *JWE_TAMPERED_CIPHERTEXT = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
                                                 "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
                                                 "AxY8DCtDaGlsbGljb3RoZQ."
                                                 "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGy."
                                                 "U0m_YmjN04DJvceFICbCVQ";

    // import the JWE
    jwe = cjose_jwe_import(JWE_TAMPERED_CIPHERTEXT, strlen(JWE_TAMPERED_CIPHERTEXT), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain3_len = 0;
    uint8_t *plain3 = cjose_jwe_decrypt(jwe, jwk, &plain3_len, &err);
    ck_assert_msg(NULL == plain3, "cjose_jwe_get_plaintext succeeded for tampered ciphertext");

    cjose_jwe_release(jwe);

    static const char *JWE_TAMPERED_IV = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
                                         "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
                                         "AxY8DCtDaGlsbGljb3RoZq."
                                         "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
                                         "U0m_YmjN04DJvceFICbCVQ";

    // import the JWE
    jwe = cjose_jwe_import(JWE_TAMPERED_IV, strlen(JWE_TAMPERED_IV), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain4_len = 0;
    uint8_t *plain4 = cjose_jwe_decrypt(jwe, jwk, &plain4_len, &err);
    ck_assert_msg(NULL == plain4, "cjose_jwe_get_plaintext succeeded for tampered IV");

    cjose_jwe_release(jwe);

    static const char *JWE_TAMPERED_CEK = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
                                          "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOq."
                                          "AxY8DCtDaGlsbGljb3RoZQ."
                                          "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
                                          "U0m_YmjN04DJvceFICbCVQ";

    // import the JWE
    jwe = cjose_jwe_import(JWE_TAMPERED_CEK, strlen(JWE_TAMPERED_CEK), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain5_len = 0;
    uint8_t *plain5 = cjose_jwe_decrypt(jwe, jwk, &plain5_len, &err);
    ck_assert_msg(NULL == plain5, "cjose_jwe_get_plaintext succeeded for tampered content encryption key");

    cjose_jwe_release(jwe);

    static const char *JWE_TAMPERED_HDR = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiB9."
                                          "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
                                          "AxY8DCtDaGlsbGljb3RoZQ."
                                          "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
                                          "U0m_YmjN04DJvceFICbCVQ";

    // import the JWE
    jwe = cjose_jwe_import(JWE_TAMPERED_HDR, strlen(JWE_TAMPERED_HDR), &err);
    ck_assert_msg(NULL != jwe,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain6_len = 0;
    uint8_t *plain6 = cjose_jwe_decrypt(jwe, jwk, &plain6_len, &err);
    ck_assert_msg(NULL == plain6, "cjose_jwe_get_plaintext succeeded for tampered header");

    cjose_jwe_release(jwe);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwe_decrypt_aes_gcm)
{
    cjose_err err;

    const char *key = JWK_OCT_32;
    const char *plain1 = "Live long and prosper.";
    char *compact1 = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..Du_9fxxV-zrReaWC.aS_rpokeuxkaPc2sykcQDCQuJCYoww.GpeKGEqd8KQ0v6JNea5aSA";
    char *compact2 = "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..Du_9fxxV-zrReaWC.aS_rpokeuxkaPc2sykcQDCQuJCYoww.Gp";

    cjose_jwk_t *jwk = cjose_jwk_import(key, strlen(key), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    cjose_jwe_t *jwe1 = cjose_jwe_import(compact1, strlen(compact1), &err);
    ck_assert_msg(NULL != jwe1,
                  "cjose_jwe_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    plain2 = cjose_jwe_decrypt(jwe1, jwk, &plain2_len, &err);
    ck_assert_msg(NULL != plain2,
                  "cjose_jwe_decrypt failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(plain2_len == strlen(plain1),
                  "length of decrypted plaintext does not match length of original, "
                  "expected: %lu, found: %lu",
                  strlen(plain1), plain2_len);
    ck_assert_msg(strncmp(plain1, plain2, plain2_len) == 0, "decrypted plaintext does not match encrypted plaintext");

    cjose_get_dealloc()(plain2);
    cjose_jwe_release(jwe1);

    cjose_jwe_t *jwe2 = cjose_jwe_import(compact2, strlen(compact2), &err);
    ck_assert_msg(NULL != jwe2,
                   "cjose_jwe_import failed: "
                   "%s, file: %s, function: %s, line: %ld",
                   err.message, err.file, err.function, err.line);

    uint8_t *plain3 = NULL;
    size_t plain3_len = 0;
    plain3 = cjose_jwe_decrypt(jwe2, jwk, &plain3_len, &err);
    ck_assert_msg(NULL == plain3,
                   "cjose_jwe_decrypt succeeded where it should have failed: "
                   "%s, file: %s, function: %s, line: %ld",
                   err.message, err.file, err.function, err.line);

    cjose_jwe_release(jwe2);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwe_decrypt_rsa)
{
    struct cjose_jwe_decrypt_rsa
    {
        const char *jwe;
        const char *plaintext;
        const char *jwk;
    };

    static const struct cjose_jwe_decrypt_rsa JWE_RSA[] = {

        // https://tools.ietf.org/html/rfc7516#appendix-A.1
        // JWE using RSAES-OAEP and AES GCM
        { "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
          "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
          "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
          "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
          "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
          "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
          "6UklfCpIMfIjf7iGdXKHzg."
          "48V1_ALb6US04U3b."
          "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
          "SdiwkIr3ajwQzaBtQD_A."
          "XFBoMYUZodetZdvTiFvSkQ",

          "The true sign of intelligence is not knowledge but imagination.",

          "{\"kty\":\"RSA\","
          "\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
          "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
          "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
          "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
          "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
          "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\","
          "\"e\":\"AQAB\","
          "\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
          "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
          "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
          "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
          "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
          "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\","
          "\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
          "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
          "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\","
          "\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
          "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
          "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\","
          "\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
          "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
          "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\","
          "\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
          "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
          "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\","
          "\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
          "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
          "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\" }" },

        // https://tools.ietf.org/html/rfc7516#appendix-A.2
        // JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
        { "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
          "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
          "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
          "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
          "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
          "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
          "-B3oWh2TbqmScqXMR4gp_A."
          "AxY8DCtDaGlsbGljb3RoZQ."
          "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
          "9hH0vgRfYgPnAHOd8stkvw",

          "Live long and prosper.",

          "{\"kty\":\"RSA\","
          "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
          "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
          "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
          "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
          "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
          "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
          "\"e\":\"AQAB\","
          "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
          "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
          "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
          "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
          "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
          "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\","
          "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
          "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
          "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\","
          "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
          "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
          "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\","
          "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
          "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
          "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\","
          "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
          "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
          "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\","
          "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
          "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
          "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\" }" },

        { NULL, NULL, NULL }
    };

    for (int i = 0; NULL != JWE_RSA[i].jwe; ++i)
    {
        cjose_err err;

        // import the JWK
        cjose_jwk_t *jwk = cjose_jwk_import(JWE_RSA[i].jwk, strlen(JWE_RSA[i].jwk), &err);
        ck_assert_msg(NULL != jwk,
                      "cjose_jwk_import failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        // import the JWE
        cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA[i].jwe, strlen(JWE_RSA[i].jwe), &err);
        ck_assert_msg(NULL != jwe,
                      "cjose_jwe_import failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        // decrypt the imported JWE
        size_t plain1_len = 0;
        uint8_t *plain1 = cjose_jwe_decrypt(jwe, jwk, &plain1_len, &err);
        ck_assert_msg(NULL != plain1,
                      "cjose_jwe_get_plaintext failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        // confirm plain == PLAINTEXT_S
        ck_assert_msg(plain1_len == strlen(JWE_RSA[i].plaintext),
                      "length of decrypted plaintext does not match length of original, "
                      "expected: %lu, found: %lu",
                      strlen(JWE_RSA[i].plaintext), plain1_len);
        ck_assert_msg(strncmp(JWE_RSA[i].plaintext, plain1, plain1_len) == 0,
                      "decrypted plaintext does not match encrypted plaintext");

        cjose_get_dealloc()(plain1);
        cjose_jwe_release(jwe);
        cjose_jwk_release(jwk);
    }
}
END_TEST

static void _cjose_test_json_serial(const char *json, const char *match_json, cjose_jwe_recipient_t *rec)
{

    cjose_jwe_t *jwe;
    cjose_err err;

    jwe = cjose_jwe_import_json(json, strlen(json), &err);
    ck_assert_msg(NULL != jwe,
                  "failed to import multi-recipient json: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    size_t decoded_len;
    char *decoded = cjose_jwe_decrypt_multi(jwe, cjose_multi_key_locator, rec, &decoded_len, &err);
    ck_assert_msg(NULL != decoded,
                  "failed to decrypt for multiple recipients: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    ck_assert_msg(memcmp(decoded, PLAINTEXT, decoded_len) == 0 && decoded_len == strlen(PLAINTEXT) + 1,
                  "decrypted plaintext does not match");
    cjose_get_dealloc()(decoded);

    decoded = cjose_jwe_export_json(jwe, &err);
    ck_assert_msg(NULL != decoded,
                  "failed to serialize JWE into json: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    ck_assert_msg(strcmp(decoded, match_json) == 0, "serialized json doesn't match expectation");

    cjose_get_dealloc()(decoded);

    cjose_jwe_release(jwe);
}

static void _cjose_test_empty_headers(cjose_jwk_t *key)
{

    cjose_jwe_t *jwe;
    cjose_err err;
    cjose_header_t *hdr;

    // regression test - if we created json without unprotected headers, we must
    // be able to read it back.

    hdr = cjose_header_new(&err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err);
    cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &err);

    cjose_jwe_recipient_t rec = { .jwk = (const cjose_jwk_t *)key, .unprotected_header = 0 };

    jwe = cjose_jwe_encrypt_multi(&rec, 1, hdr, 0, (uint8_t *)"", 1, &err);
    ck_assert_msg(NULL != jwe,
                  "failed to encrypt test data: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    char *json = cjose_jwe_export_json(jwe, &err);
    ck_assert_msg(NULL != json,
                  "failed to serialize test data: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    cjose_jwe_release(jwe);
    cjose_header_release(hdr);

    // import the json back

    jwe = cjose_jwe_import_json(json, strlen(json), &err);
    ck_assert_msg(NULL != jwe,
                  "failed to import test data: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    size_t len;
    char *test = (char *)cjose_jwe_decrypt(jwe, key, &len, &err);
    ck_assert_msg(NULL != test,
                  "failed to decrypt test data: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    ck_assert_msg((len == 1) && (*test == 0), "Decrypted data does not match original");

    free(test);
    free(json);
    cjose_jwe_release(jwe);
}

START_TEST(test_cjose_jwe_multiple_recipients)
{

    char *rsa[] = { "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"pXldOFJS1PKXlkkkcCKtBt6efl84jkZinEzVF1HcksvO_b"
                    "QUFJbUPcZwyzKk8fYnGbu0LwnY3hhCSDk-Ki8S2h_8VOiR7AY2ptI_TjeGp0DDqSnmJEdDrwIbw0yGTgOHZ63xms0aE4"
                    "fv9tdrw5U4v_A3AfOwUtCyxuyZP_7WlNj0sMsWwiyp0BGvCUB4xuhVtsEsbSWvSAO8CYHEy3fVGZ6bLXh7DbF7WlbfZ9K"
                    "bZCiLhP4RAmNtBQQ8jYpzTedr6qGvAz8TNl7mSfG7aQk465xCHOCrk0TLrHMDI1G4ZaFAkhXeg-KsoC8C1Mktaz3zLZwam_"
                    "ZsMHyl5UNxl4MzZQ\",\"d\":\"Zgss2JGz8QxVPOGILfrEVysr9GSGPP7cyuR6uHHMI166HCxUAcptwlbAsh5eJ7STskPVv"
                    "vhEm9m77kwWsO7sokT9V-NAMZw3UbLwRSzqxfOjdYuYGCE2dRNIyaxEWpHEi8Rx7PO0s_ytl7yLAUbhg0QAuBxuTPPUe-XmL"
                    "9fYvlr6mxbA0Pxtr_ZcisDOL5gUWhpb-rWzIUH_G9519J_Th7z9_C5v3q88UiA7VomBiMg8TKz23GKsG4TPmGnAW7ctHKP"
                    "2b3xl6b868IuPOr1YqqlnOCh6T9-mKuOlCMcU89UR5TTgRn0HoRQBumbw3qYGn8YbxcW38jbR9imKTcbrPQ\",\""
                    "p\":\"1v7ar4cL2Jh0h9DigLcyC1F8-MlDKtDzrqhpJsk49aYoc4vsdsBYUQCKbnarxhmItbLMq178p8nu31qSYXhkg0D-YeL"
                    "o3RIbLqfC1HElVp6E3U41L7AGSjg6WdwInfqwfRfiCNNPKKtb-gHbtEP54PezqdcIXfjSlFim1vBmCA0\",\""
                    "q\":\"xQigtlXLQX8J93V_PK2ZRGvTAFHDTZkJ-1CUPphOXZNezvMzEgv4tPsHJPUZU_muFjwlEs17qGO8xaZlfU-ohD13h"
                    "kpVh_xqJj6Cl5kOVXIW6COE_M6dGGJDzCIiXurN3QjQXututMlhO-anmRspaI3v6vby2JXjZIdJqpm6ark\","
                    "\"dp\":\"C4VswqtB_0FsPTr8aFlo3SJoyAxBBTJdXKa5u9Jcsw1MbaS570MveGfHA1RosBz-Ln5-aVCVyYgQvPdlkMO"
                    "a303EVAqM4AvwWPe0gR3vGk00YYenYf7U13Vb6yTXcV_VxV5aRo7MVymXrDYdR_O8mEmt3xQe5qpG3pxBlJMdZKE\","
                    "\"dq\":\"nIyBXL4H868jVRlnEegAeeuNx5gvK-1nj-VzE9Thltnrn1R-BF28qtc00vlmuWENH5-D-U-Ia79rEkNmKc1r4"
                    "D4SRIG1OYmlMWPDUP4L9Hnkl2b5WAA1s1UH9x473tyC2pcRMAmxeTTz66sVCMIbAXac5Dx3sPxOouYW8tSX2Ak\","
                    "\"qi\":\"PphvSiKY95wBif4o2AUOxk9p7v2KdMZ9FY92v-moGML8k5_Gy7xHYUIzoeGGwzp_4V4kI1zTct76K-Q"
                    "zDebf2wv1_v4AKFjcAUleEpDVVnGPQ3-ftftkc0UFmkoKorHLZ5Q5ZjKxa313V1pYQwbdra54xabl7LvPStYJ3asw2Yc\"}",

                    "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"zi97QZsWWOkQ1x1gnZvcJPh1jse60KxJMHruvWI0D3klI3_"
                    "29gamVgkdl9M0_t0OCq0PZZB2jzXp7b7M07sYg6MEyjOQ61KznN-fEm1QKjXznIUQghOll5u04Tjmm8dXtWNV6on2LpsN1"
                    "J9hz3088ekOaYwdTntx2fZPDRmxYOBJOoX9sswW6iL-PrFCcLtwcpsyJsU_A9Am7whHQSS2dmzM5ruz7P6d9NDwlPhGLXV"
                    "qRYlPc1kr3_vzwLDI8Yo1GUEzdEQ2HWWP7dL2ySl8s8ExoUTcl8AKT5w805ZmpfmhK1mxixFpbCTvJX3WPo3GWJ614XO6"
                    "lZZRoh5ypt0Rsw\","
                    "\"d\":\"vpmIAFrEasZwydqfYLMe65I-4hFicdqCAe3yWmG4rIEZwtpdSotVIn1kvOACwoNIorfeXs4Pu01khWF26Vew"
                    "TqfZGq5WjiMyZJcX7qncjFi5bXxYiVZuIltO91BpZaH-Q3CjkJ-eUvEE9QOtIGiueRYvO4TJ5q4YzhtycjLJFTo3vIDX"
                    "woOb4R4TW5qtSlzg0baW4qEyMzqiink9kT6OvXwt6FC6RMquLlPtOYzr5KvoaBf-qbBUU9L5M9bfmPUjgk_Suz9QLYOgE"
                    "ZDxUj0jyJiXgCnjidqd094iCHpBIevByfhLJmBqjIlPAZ9O1svHeA0jpE73E6ZZyKDOES3qgQ\","
                    "\"p\":\"6oIBg20lS5YIESnUM7SpGLaWCMem-c-IRolnN6gRLHkpb_mudUhO-RuQNYUzB8we5dmBkVyJxR2W4J79rFj"
                    "bmilUO_8NcGYvGPYM_rOzPIP02Sltaea_vrNr-dS6-Q-lICL6845E8VeTBKRRKRr-uf-AWZfrr-ncNZaTuqa9rsE\","
                    "\"q\":\"4RT608xr6KN1Q2uj9ADXu5ZY3k1-Lf7RrtwXO-5U56777Ww7POvZi5EZoySEgWeBA426Ty5QIm0oqClCSlS0s"
                    "CkYwrno0zEePsvJ9nb0BHRi_x1NVL_1iuL0dy3g5LgThhvaoMTQwiSNRRFveQhRYgB89eHIHxPw_FYSFl780XM\","
                    "\"dp\":\"rPrUzvM1rXmv3akzJCjBCr-0ECnlWyPga9dy0bUhZeLB1B0iuNRrnIjeaPwl1jyVFgrI7kaKQWJAJtRgXj"
                    "71TdPqlI7ghOZ7Gzh0AXTgY2UauQ077gANtEd5AEIQ4SLPNNNYtUteQ3_LrILgcye8ecqkDHJpocspakX2FppkFIE\","
                    "\"dq\":\"hgBAiGG2iKzv_jCSTo1F4pdS1x5ZlbaUTT8Y0gRFJh3GPIZoCg_71xyOn9L41DWz2FLDbaqL6MMGJn9RyQD"
                    "_BbWh2SRnWXxvnkEjPwl4o0JLQcjHJkKWQ5Z0ppN4xZJVhU0F7xrdkgfC1zDXJb5u_SJ_Qr-lreLoYMI5SHpKl8M\","
                    "\"qi\":\"Boxvcq8bIswXo8BPCcZurLjacS0TlUzbs2mLJD3noJKd361fgGoO2XdG94bqkbGg-5wbGDZL2YqGKlA2Y"
                    "j8yU8ZiULaLsm3HadNVxkLTy90j59urbf0MSnMkljACZUfH2yfxVbzgZd0DWS7eDtMBP4VrQ_tQmR_djRaLOMh5yxg\"}" };

    char *multi_json
        = "{\"protected\": \"eyJlbmMiOiAiQTI1NkdDTSJ9\", \"iv\": \"cGHj6gmN4kC0cLTh\", \"ciphertext\": "
          "\"ffgBXOZoYfCxPrbXXe4qOK0bll4F74wo3qGObUqllCdM6Vp4SyOagnFDUFMAwSA_-vVCYW37dJIBOExDQgGK0Q48cVKfiTQ5R6iKIFs6Fkc6FfXfTNKa_"
          "M46Ay66lY3kFHGqWMtS6DcQs9nYltUf8uo0hEsUl1D1eA\", \"tag\": \"5LF0d_O23WKHq4c1ijaJqg\", \"recipients\": [{\"header\": "
          "{\"kid\": \"test-0\", \"alg\": \"RSA-OAEP\"}, \"encrypted_key\": "
          "\"hfrpxvv57nnZKJ5Whic5nEvMp2Iob5JSkht25fGRbRBj3Q9_hgbCKiMV10sSX5qVLwIsfdfSYH3QvvsI_aPV4qB326cp7SuHDgvqdKnQs-"
          "qDwHrg7Erc9tJFjpR-t_VfnV8wZvEP92xvCaZ4-kx86718Op2Gb82M7ojaHufwoxN_"
          "Al5oNrBNZgLZgvKROT7HmvlxHSCr0XamI8txtOt7pawZ4ENqVc1VKGYu7il-h4htMvYT7Ix0OSBWoAG1NxW-tqcD75dR_"
          "SEmPkgbeC8ofbulq1lL22PLAQzpi1Op69tOIvBQ3j0JZDOUpSQajYNAyZdD26BHV_STVb-hkUCFmA\"}, {\"header\": {\"kid\": \"test-1\", "
          "\"alg\": \"RSA1_5\"}, \"encrypted_key\": "
          "\"Hro4KVp4KfI-7NBtAPJ67N9Oas0RrU8qs01o6fOGiVtAO9yvfvzmC6dSYOAmrhMfASm5EI3K_miQT40agyRUC5wpfV6x5NKTFaJRgGJeF5xdQyE_"
          "fVNthG67GLcc-_LY5Shu2Jm5Ih1pSb4mRl6zOVBVw0HroPJLiMmRU3ai5YFLNp7M87igWHznkFWFljLONVcgV7QTJ4KDEhJUmasDqCpQ_kf5_"
          "b5u4aNWqNv4FMMTgQ5XcfCVHOnYjhD3HkeqsWe4VnL3GFKBU96Lwtff-qzC55DLxtUKDrP5ZRdFKnxJX1t_X7DzgYQYxr19fx6Y-aXmflBAqIdN5-"
          "OyENlWxQ\"}]}";
    char *single_json = "{\"protected\":\"eyJlbmMiOiAiQTI1NkdDTSJ9\",\"iv\":\"cGHj6gmN4kC0cLTh\",\"ciphertext\":"
                        "\"ffgBXOZoYfCxPrbXXe4qOK0bll4F74wo3qGObUqllCdM6Vp4SyOagnFDUFMAwSA_-"
                        "vVCYW37dJIBOExDQgGK0Q48cVKfiTQ5R6iKIFs6Fkc6FfXfTNKa_M46Ay66lY3kFHGqWMtS6DcQs9nYltUf8uo0hEsUl1D1eA\","
                        "\"tag\":\"5LF0d_O23WKHq4c1ijaJqg\",\"recipients\":[{\"header\":{\"kid\":\"test-1\",\"alg\":\"RSA1_5\"},"
                        "\"encrypted_key\":\"Hro4KVp4KfI-7NBtAPJ67N9Oas0RrU8qs01o6fOGiVtAO9yvfvzmC6dSYOAmrhMfASm5EI3K_"
                        "miQT40agyRUC5wpfV6x5NKTFaJRgGJeF5xdQyE_fVNthG67GLcc-_"
                        "LY5Shu2Jm5Ih1pSb4mRl6zOVBVw0HroPJLiMmRU3ai5YFLNp7M87igWHznkFWFljLONVcgV7QTJ4KDEhJUmasDqCpQ_kf5_"
                        "b5u4aNWqNv4FMMTgQ5XcfCVHOnYjhD3HkeqsWe4VnL3GFKBU96Lwtff-qzC55DLxtUKDrP5ZRdFKnxJX1t_X7DzgYQYxr19fx6Y-"
                        "aXmflBAqIdN5-OyENlWxQ\"}]}";
    char *single_flat_json
        = "{\"protected\": \"eyJlbmMiOiAiQTI1NkdDTSJ9\", \"iv\": \"cGHj6gmN4kC0cLTh\", \"ciphertext\": "
          "\"ffgBXOZoYfCxPrbXXe4qOK0bll4F74wo3qGObUqllCdM6Vp4SyOagnFDUFMAwSA_-vVCYW37dJIBOExDQgGK0Q48cVKfiTQ5R6iKIFs6Fkc6FfXfTNKa_"
          "M46Ay66lY3kFHGqWMtS6DcQs9nYltUf8uo0hEsUl1D1eA\", \"tag\": \"5LF0d_O23WKHq4c1ijaJqg\", \"header\": {\"kid\": \"test-1\", "
          "\"alg\": \"RSA1_5\"}, \"encrypted_key\": "
          "\"Hro4KVp4KfI-7NBtAPJ67N9Oas0RrU8qs01o6fOGiVtAO9yvfvzmC6dSYOAmrhMfASm5EI3K_miQT40agyRUC5wpfV6x5NKTFaJRgGJeF5xdQyE_"
          "fVNthG67GLcc-_LY5Shu2Jm5Ih1pSb4mRl6zOVBVw0HroPJLiMmRU3ai5YFLNp7M87igWHznkFWFljLONVcgV7QTJ4KDEhJUmasDqCpQ_kf5_"
          "b5u4aNWqNv4FMMTgQ5XcfCVHOnYjhD3HkeqsWe4VnL3GFKBU96Lwtff-qzC55DLxtUKDrP5ZRdFKnxJX1t_X7DzgYQYxr19fx6Y-aXmflBAqIdN5-"
          "OyENlWxQ\"}";

    const char *algs[2] = { CJOSE_HDR_ALG_RSA_OAEP, CJOSE_HDR_ALG_RSA1_5 };

    cjose_err err;

    cjose_jwe_recipient_t rec[2];

    for (int i = 0; i < 2; i++)
    {

        char kid[32];

        cjose_jwk_t *jwk = cjose_jwk_import(rsa[i], strlen(rsa[i]), &err);
        ck_assert_msg(NULL != jwk,
                      "cjose_jwk_import failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        memset(kid, 0, 32);
        snprintf(kid, 31, "test-%d", i);

        ck_assert_msg(cjose_jwk_set_kid(jwk, kid, strlen(kid), &err),
                      "cjose_jwk_set_kid failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        rec[i].jwk = jwk;

        cjose_header_t *unprotected;

        ck_assert_msg((unprotected = cjose_header_new(&err)) && cjose_header_set(unprotected, "kid", kid, &err)
                          && cjose_header_set(unprotected, CJOSE_HDR_ALG, algs[i], &err),
                      "failed to set KID into a header: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);
        rec[i].unprotected_header = unprotected;
    }

    rec[2].jwk = NULL;

    cjose_header_t *protected_header = cjose_header_new(&err);

    ck_assert_msg(cjose_header_set(protected_header, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    cjose_jwe_t *jwe = cjose_jwe_encrypt_multi(rec, 2, protected_header, NULL, PLAINTEXT, strlen(PLAINTEXT) + 1, &err);
    ck_assert_msg(NULL != jwe,
                  "failed to encrypt to multiple recipients:"
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    size_t decoded_len;
    uint8_t *decoded = cjose_jwe_decrypt_multi(jwe, cjose_multi_key_locator, rec, &decoded_len, &err);
    ck_assert_msg(NULL != decoded,
                  "failed to decrypt for multiple recipients: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);
    ck_assert_msg(memcmp(decoded, PLAINTEXT, decoded_len) == 0 && decoded_len == strlen(PLAINTEXT) + 1,
                  "decrypted plaintext does not match");

    char *ser = cjose_jwe_export(jwe, &err);
    ck_assert_msg(ser == NULL && err.code == CJOSE_ERR_INVALID_ARG,
                  "succeeded in creating compact serialization for multiple recipients");

    cjose_jwe_release(jwe);
    cjose_get_dealloc()(decoded);

    _cjose_test_json_serial(multi_json, multi_json, rec);
    _cjose_test_json_serial(single_json, single_flat_json, rec);
    _cjose_test_json_serial(single_flat_json, single_flat_json, rec);
    _cjose_test_empty_headers(rec[0].jwk);

    for (int i = 0; i < 2; i++)
    {
        cjose_jwk_release(rec[i].jwk);
        cjose_header_release(rec[i].unprotected_header);
    }

    cjose_header_release(protected_header);
}
END_TEST

Suite *cjose_jwe_suite()
{
    Suite *suite = suite_create("jwe");

    TCase *tc_jwe = tcase_create("core");
    tcase_set_timeout(tc_jwe, 120.0);
    tcase_add_test(tc_jwe, test_cjose_jwe_node_jose_encrypt_self_decrypt);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_short);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_empty);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_large);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_many);
    tcase_add_test(tc_jwe, test_cjose_jwe_decrypt_aes);
    tcase_add_test(tc_jwe, test_cjose_jwe_decrypt_aes_gcm);
    tcase_add_test(tc_jwe, test_cjose_jwe_decrypt_rsa);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_header);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_key);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_content);
    tcase_add_test(tc_jwe, test_cjose_jwe_import_export_compare);
    tcase_add_test(tc_jwe, test_cjose_jwe_import_invalid_serialization);
    tcase_add_test(tc_jwe, test_cjose_jwe_decrypt_bad_params);
    tcase_add_test(tc_jwe, test_cjose_jwe_multiple_recipients);
    suite_add_tcase(suite, tc_jwe);

    return suite;
}
