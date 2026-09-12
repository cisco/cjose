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
#include "include/jws_int.h"
#include "include/util_int.h"
#include <openssl/rand.h>

// a JWK to be re-used for unit tests
static const char *JWK_COMMON
    = "{ \"kty\": \"RSA\", "
      "\"e\": \"AQAB\", "
      "\"n\": "
      "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
      "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
      "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
      "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
      "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
      "\"d\": "
      "\"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-"
      "twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-"
      "ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-"
      "duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\", "
      "\"p\": "
      "\"7X_Hk-tohqmSp8Wv1UcjLw-_DyzYZTmHuXblxWJUk54shbujVU6MQg0_6NIGi0-9Y5_yjiUQMM4wRqrMevYxqMnSzDherN1fI-nWv-"
      "PNDrxEFObIFEYJy1vHQe1fqgraoLkgVwyzvrDXtUN_EnSXyALhBdr8vLUnCjkG7-j2UV8\", "
      "\"q\": "
      "\"4gPgtf7FT91-FmkkNsrpK0J4Fp8jG1N0GuM30NvS4D715NWOKeuoUi1Ius3yHNdzo9uwLJgY7xJMJlr3ZSmcldwFLBKGVkLctOVLqDWrBLMwD-"
      "fPkQVV1FeRfso9bMUcprvSI2RbmIccF02MuLprltmbTdgOJA47_OqjmkHYV-U\", "
      "\"dp\": "
      "\"VIJbae8iSoicfsaBQssFYgGgYq36ckp-WShNqmbK4ZwvC4cxH3HLxtUgIKBbY8cEBSctEBdwI227D-pGyJpCIWVvdOu6BJjg-"
      "c6Dc9SDavLi5u0X1N73LT2DMZpdqAwkr3wwXclPTFNw7jcOSGrkd29O0t6RgDSVp7WTGlszCtE\", "
      "\"dq\": "
      "\"ZWB_5qJENrKO39aBW-Jf-_twihUPVi50oarRWml_iP40pVP01HDTqyiMut2tf6pUQGdF-nqulG2Mopei6Ell5wItf7s_"
      "bmnHPYysBuMrtov5PuknfVD7UqeEp25nZuZzF4aflyhovV29B-bM-_8CS0OIGb6TeTC5T5SflY17UNE\", "
      "\"qi\": "
      "\"RowmdelfiEBdqfBCSb3yblUKhwJsbyg6HtcugIVOC1yDxD5sZ0cjJPnXj7TJkrC0tICQ50MlPY5F650D9pvACIYnvrGEwsq757Lxg5nqshvuSC-7i1TMkv7_"
      "uPBmIxRfzqsnh_hVhxLgSUW1NI6_ncwk9vDQqpkY6qBirgvbyO0\" }";

static const char *JWK_COMMON_OCT
    = "{ \"kty\": \"oct\", "
      "\"k\": \"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }";

static const char *JWK_COMMON_EC = "{ \"kty\":\"EC\","
                                   "\"crv\":\"P-256\","
                                   "\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\","
                                   "\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\","
                                   "\"d\":\"RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM\" }";

static const char *JWK_COMMON_EC_SECP_256K1 = "{ \"kty\":\"EC\","
                                              "\"crv\":\"secp256k1\","
                                              "\"x\":\"dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A\","
                                              "\"y\":\"36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA\","
                                              "\"d\":\"rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw\" }";

// RFC 8037 appendix A.1: an Ed25519 key pair
static const char *JWK_COMMON_OKP_ED25519 = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
                                            "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\","
                                            "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

// an Ed448 key pair
static const char *JWK_COMMON_OKP_ED448 = "{\"kty\":\"OKP\",\"crv\":\"Ed448\","
                                          "\"d\":\"oGPIKJFtuoGB5jlVOAndK8d9MtZcYu-1Kh4ISCqNpy2tw8NbVtNVgUHzzkSx0WaFkqQHalP3fiul\","
                                          "\"x\":\"j531A8-05AW0GGOnvpQyiDrC3eBrHW9w1Q8YjhYZiHtBn6czxQjpluO5_sZ_xEUpQxbtW0TRjvUA\"}";

// RFC 7748 section 6.1: Alice's X25519 key pair, a key agreement key that must not sign
static const char *JWK_COMMON_OKP_X25519 = "{\"kty\":\"OKP\",\"crv\":\"X25519\","
                                           "\"d\":\"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\","
                                           "\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\"}";

// a JWS encrypted with the above JWK_COMMON key
static const char *JWS_COMMON
    = "eyAiYWxnIjogIlBTMjU2IiB9."
      "SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0"
      "aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.0YJo4r9gbI2nZ2_1_"
      "KLTY3i5SRcZvahRuToavqBvLbm87pN7IYx8YV9kwKQclMW2ASpbEAzKNIJfQ3FycobRwZGtqCI9sRUo0vQvkpb3HIS6HKp3Kvur57J7LcZhz7uNIxzUYNQSg4EWp"
      "whF9FnGng7bmU8qjNPiXCWfQ-n74gopAVzd3KDJ5ai7q66voRc9pCKJVbsaIMHIqcl9OPiMdY5Hz3_PgBalR2632HOdpUlIMvnMOL3EQICvyBwxaYPbhMcCpEc3_"
      "4K-sywOGiCSp9KlaLcRq0knZtAT0ynJszaiOwfR-W18PEFLfGclpeR6e_gop9mq69t36wK7KRUjrQ";

static const char *_self_get_jwk_by_alg(const char *alg)
{
    if ((strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
        return JWK_COMMON_OCT;
    if (strcmp(alg, CJOSE_HDR_ALG_ES256K) == 0)
        return JWK_COMMON_EC_SECP_256K1;
    if ((strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
        return JWK_COMMON_EC;
    if (strcmp(alg, CJOSE_HDR_ALG_ED25519) == 0)
        return JWK_COMMON_OKP_ED25519;
    if (strcmp(alg, CJOSE_HDR_ALG_ED448) == 0)
        return JWK_COMMON_OKP_ED448;
    return JWK_COMMON;
}

static void _self_sign_self_verify(const uint8_t *plain1, size_t plain1_len, const char *alg, cjose_err *err)
{
    const char *s_jwk = _self_get_jwk_by_alg(alg);
    cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), err);

    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // set header for JWS
    cjose_header_t *hdr = cjose_header_new(err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, alg, err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // create the JWS
    cjose_jws_t *jws1 = cjose_jws_sign(jwk, hdr, plain1, plain1_len, err);
    ck_assert_msg(NULL != jws1,
                  "cjose_jws_sign failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);
    ck_assert(hdr == cjose_jws_get_protected(jws1));

    // get the compact serialization of JWS
    const char *compact = NULL;
    ck_assert_msg(cjose_jws_export(jws1, &compact, err),
                  "cjose_jws_export failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // deserialize the compact representation to a new JWS
    cjose_jws_t *jws2 = cjose_jws_import(compact, strlen(compact), err);
    ck_assert_msg(NULL != jws2,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws2, jwk, err),
                  "cjose_jws_verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // get the verified plaintext
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws2, &plain2, &plain2_len, err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err->message, err->file, err->function, err->line);

    // confirm equal headers
    ck_assert(json_equal((json_t *)cjose_jws_get_protected(jws1), (json_t *)cjose_jws_get_protected(jws2)));

    // confirm plain2 == plain1
    ck_assert_msg(plain2_len == plain1_len,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  plain1_len, plain2_len);
    ck_assert_msg(memcmp(plain1, plain2, plain2_len) == 0, "verified plaintext does not match signed plaintext");

    cjose_header_release(hdr);
    cjose_jws_release(jws1);
    cjose_jws_release(jws2);
    cjose_jwk_release(jwk);
}

static void _self_sign_self_verify_all_algs(const uint8_t *plain, size_t plain_len, cjose_err *err)
{
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_PS256, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_PS384, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_PS512, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_RS256, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_RS384, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_RS512, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_HS256, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_HS384, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_HS512, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ES256, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ES256K, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ES384, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ES512, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ED25519, err);
    _self_sign_self_verify(plain, plain_len, CJOSE_HDR_ALG_ED448, err);
}

START_TEST(test_cjose_jws_self_sign_self_verify)
{
    cjose_err err;
    static const uint8_t plain[] = "If you reveal your secrets to the wind, you should not blame the "
                                   "wind for revealing them to the trees. — Kahlil Gibran";
    _self_sign_self_verify_all_algs(plain, sizeof(plain) - 1, &err);
}
END_TEST

START_TEST(test_cjose_jws_verify_es256k)
{
    cjose_err err;
    static const char *JWK = "{ \"kty\":\"EC\","
                             "\"crv\":\"secp256k1\","
                             "\"x\":\"dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A\","
                             "\"y\":\"36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA\" }";
    static const char *JWS = "eyJhbGciOiJFUzI1NksifQ."
                             "RVMyNTZLIGludGVyb3BlcmFiaWxpdHkgdGVzdA."
                             "AUxIItkz7WGblbT8WkRzeCTD_k30iOdSVPqEMBUC2qC8BxbrPVTzubweSB2lv27Dsf554vVSrqcwNfE4DHmfPA";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);
    ck_assert(CJOSE_JWK_EC_SECP_256K1 == cjose_jwk_EC_get_curve(jwk, &err));

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed: %s", err.message);

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert(cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err));
    ck_assert_int_eq(strlen("ES256K interoperability test"), plaintext_len);
    ck_assert(0 == memcmp("ES256K interoperability test", plaintext, plaintext_len));

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_es256k_rejects_wrong_curve)
{
    cjose_err err;
    static const char *JWS = "eyJhbGciOiJFUzI1NksifQ."
                             "RVMyNTZLIGludGVyb3BlcmFiaWxpdHkgdGVzdA."
                             "AUxIItkz7WGblbT8WkRzeCTD_k30iOdSVPqEMBUC2qC8BxbrPVTzubweSB2lv27Dsf554vVSrqcwNfE4DHmfPA";
    cjose_jwk_t *p256 = cjose_jwk_import(JWK_COMMON_EC, strlen(JWK_COMMON_EC), &err);
    cjose_jwk_t *secp256k1 = cjose_jwk_import(JWK_COMMON_EC_SECP_256K1, strlen(JWK_COMMON_EC_SECP_256K1), &err);
    ck_assert(NULL != p256);
    ck_assert(NULL != secp256k1);

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert(NULL != header);
    ck_assert(cjose_header_set(header, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ES256K, &err));
    cjose_jws_t *jws = cjose_jws_sign(p256, header, (const uint8_t *)"test", 4, &err);
    ck_assert(NULL == jws);
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    ck_assert(cjose_header_set(header, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ES256, &err));
    jws = cjose_jws_sign(secp256k1, header, (const uint8_t *)"test", 4, &err);
    ck_assert(NULL == jws);
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, p256, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    cjose_header_release(header);
    cjose_jws_release(jws);
    cjose_jwk_release(secp256k1);
    cjose_jwk_release(p256);
}
END_TEST

// RFC 9864 fully-specified {"alg":"Ed25519"} over the RFC 8037 appendix A.4
// payload "Example of Ed25519 signing" with the RFC 8037 appendix A.1 key; the
// (deterministic) signature was produced with "openssl pkeyutl -sign -rawin"
static const char *JWS_ED25519 = "eyJhbGciOiJFZDI1NTE5In0."
                                 "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
                                 "UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ";
static const uint8_t PLAINTEXT_ED25519[] = "Example of Ed25519 signing";

// RFC 8037 appendix A.2: the public half of the appendix A.1 key
static const char *JWK_RFC8037_A2 = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

// an Ed448 key pair and the RFC 9864 fully-specified {"alg":"Ed448"} over the
// same payload with it, signed with "openssl pkeyutl -sign -rawin" as well
static const char *JWK_ED448 = "{\"kty\":\"OKP\",\"crv\":\"Ed448\","
                               "\"d\":\"TN58WZuh-iWvRvIW-O6sXHjLBTL78bG030WeJZ2I2-ArR8exchehxoA5TXr-3Skuw1qagrV6mjdm\","
                               "\"x\":\"EwEiD2H04mq1APe4WwLHGWFqURrhfJsXvHQdYAyuOUJQ0wV2DTzOswRxeZbpt-JDdZuTS-7XTaUA\"}";
// the public half of the Ed448 key pair
static const char *JWK_ED448_PUB
    = "{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"EwEiD2H04mq1APe4WwLHGWFqURrhfJsXvHQdYAyuOUJQ0wV2DTzOswRxeZbpt-JDdZuTS-7XTaUA\"}";
static const char *JWS_ED448 = "eyJhbGciOiJFZDQ0OCJ9."
                               "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
                               "lNW705OHs6eVsLWubNgE_MYb5ouwmCDM5yTit2oNcvbL2e4oBiOQG1y7cJAd57uNIKMWFw-8CFWAZ1QFn7Jnc8__MYvyFL6P"
                               "VgNIx0ZCvFfaUkfL7Fee10JdLcEzHMlap_ydB8cpxwAgf4OlsA2tljcA";

START_TEST(test_cjose_jws_verify_ed25519)
{
    cjose_err err;

    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RFC8037_A2, strlen(JWK_RFC8037_A2), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    cjose_jws_t *jws_ok = cjose_jws_import(JWS_ED25519, strlen(JWS_ED25519), &err);
    ck_assert_msg(NULL != jws_ok, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err), "cjose_jws_verify failed: %s", err.message);

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert(cjose_jws_get_plaintext(jws_ok, &plain, &plain_len, &err));
    ck_assert_int_eq(sizeof(PLAINTEXT_ED25519) - 1, plain_len);
    ck_assert(0 == memcmp(PLAINTEXT_ED25519, plain, plain_len));

    // verifying the same JWS again (as a loop over candidate keys does) must work too
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err), "second cjose_jws_verify failed: %s", err.message);
    cjose_jws_release(jws_ok);

    // tampered signature
    static const char *JWS_TAMPERED_SIG = "eyJhbGciOiJFZDI1NTE5In0."
                                          "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
                                          "UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAg";
    cjose_jws_t *jws_ts = cjose_jws_import(JWS_TAMPERED_SIG, strlen(JWS_TAMPERED_SIG), &err);
    ck_assert_msg(NULL != jws_ts, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(!cjose_jws_verify(jws_ts, jwk, &err), "cjose_jws_verify succeeded with tampered signature");
    ck_assert_int_eq(CJOSE_ERR_CRYPTO, err.code);
    cjose_jws_release(jws_ts);

    // tampered content ("Example of tampered Ed25519 signing")
    static const char *JWS_TAMPERED_CONTENT
        = "eyJhbGciOiJFZDI1NTE5In0."
          "RXhhbXBsZSBvZiB0YW1wZXJlZCBFZDI1NTE5IHNpZ25pbmc."
          "UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ";
    cjose_jws_t *jws_tc = cjose_jws_import(JWS_TAMPERED_CONTENT, strlen(JWS_TAMPERED_CONTENT), &err);
    ck_assert_msg(NULL != jws_tc, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(!cjose_jws_verify(jws_tc, jwk, &err), "cjose_jws_verify succeeded with tampered content");
    ck_assert_int_eq(CJOSE_ERR_CRYPTO, err.code);
    cjose_jws_release(jws_tc);

    cjose_jwk_release(jwk);
}
END_TEST

static void _sign_and_compare(const char *s_jwk, const char *alg, const uint8_t *plain, size_t plain_len, const char *expected)
{
    cjose_err err;

    cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(NULL != hdr);
    ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err));

    // sign: an EdDSA signature is deterministic (RFC 8032), so the JWS must
    // match the reference exactly
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL != jws, "cjose_jws_sign [%s] failed: %s", alg, err.message);
    ck_assert(hdr == cjose_jws_get_protected(jws));
    const char *compact = NULL;
    ck_assert(cjose_jws_export(jws, &compact, &err));
    ck_assert_str_eq(expected, compact);
    cjose_jws_release(jws);

    // verify the reference
    jws = cjose_jws_import(expected, strlen(expected), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify [%s] failed: %s", alg, err.message);
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    ck_assert(cjose_jws_get_plaintext(jws, &plain2, &plain2_len, &err));
    ck_assert_int_eq(plain_len, plain2_len);
    ck_assert(0 == memcmp(plain, plain2, plain_len));
    cjose_jws_release(jws);

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}

START_TEST(test_cjose_jws_sign_ed25519)
{
    _sign_and_compare(JWK_COMMON_OKP_ED25519, CJOSE_HDR_ALG_ED25519, PLAINTEXT_ED25519, sizeof(PLAINTEXT_ED25519) - 1, JWS_ED25519);

    // a second reference: {"alg":"Ed25519"} over "{}" with another key
    static const char *JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"VoU6Pm8SOjz8ummuRPsvoJQOPI3cjsdMfUhf2AAEc7s\","
                             "\"x\":\"l11mBSuP-XxI0KoSG7YEWRp4GWm7dKMOPkItJy2tlMM\"}";
    static const char *JWS
        = "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ";
    _sign_and_compare(JWK, CJOSE_HDR_ALG_ED25519, (const uint8_t *)"{}", 2, JWS);
}
END_TEST

START_TEST(test_cjose_jws_sign_verify_ed448)
{
    _sign_and_compare(JWK_ED448, CJOSE_HDR_ALG_ED448, PLAINTEXT_ED25519, sizeof(PLAINTEXT_ED25519) - 1, JWS_ED448);
}
END_TEST

START_TEST(test_cjose_jws_ed25519_rejects_wrong_key)
{
    cjose_err err;
    static const uint8_t plain[] = "test";

    cjose_jwk_t *ed25519 = cjose_jwk_import(JWK_COMMON_OKP_ED25519, strlen(JWK_COMMON_OKP_ED25519), &err);
    cjose_jwk_t *ed448 = cjose_jwk_import(JWK_COMMON_OKP_ED448, strlen(JWK_COMMON_OKP_ED448), &err);
    cjose_jwk_t *x25519 = cjose_jwk_import(JWK_COMMON_OKP_X25519, strlen(JWK_COMMON_OKP_X25519), &err);
    cjose_jwk_t *ec = cjose_jwk_import(JWK_COMMON_EC, strlen(JWK_COMMON_EC), &err);
    cjose_jwk_t *pub = cjose_jwk_import(JWK_RFC8037_A2, strlen(JWK_RFC8037_A2), &err);
    ck_assert(NULL != ed25519 && NULL != ed448 && NULL != x25519 && NULL != ec && NULL != pub);

    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(NULL != hdr);

    const struct
    {
        const char *alg;
        cjose_jwk_t *jwk;
    } bad[] = {
        { CJOSE_HDR_ALG_ED25519, ec },     // Ed25519 takes an OKP key
        { CJOSE_HDR_ALG_ED25519, x25519 }, // ... of the Ed25519 curve, not a key agreement key (RFC 8037 section 3.1)
        { CJOSE_HDR_ALG_ED25519, ed448 },  // ... and not an Ed448 key (RFC 9864)
        { CJOSE_HDR_ALG_ED448, ed25519 },  // Ed448 takes an Ed448 key
        { CJOSE_HDR_ALG_ED448, x25519 },   { CJOSE_HDR_ALG_ES256, ed25519 }, // an OKP key does not serve the ECDSA family
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, bad[i].alg, &err));
        cjose_jws_t *jws = cjose_jws_sign(bad[i].jwk, hdr, plain, sizeof(plain) - 1, &err);
        ck_assert_msg(NULL == jws, "cjose_jws_sign [%s] accepted a key of the wrong type (case %zu)", bad[i].alg, i);
        ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    }

    // signing needs the private key: the library refuses a public-only key
    // itself, since OpenSSL 3.0.0 through 3.0.7 signs with the missing private
    // key instead of failing (3.0.8 added the guard)
    cjose_jwk_t *ed448_pub = cjose_jwk_import(JWK_ED448_PUB, strlen(JWK_ED448_PUB), &err);
    ck_assert(NULL != ed448_pub);
    const struct
    {
        const char *alg;
        cjose_jwk_t *jwk;
    } pub_only[] = { { CJOSE_HDR_ALG_ED25519, pub }, { CJOSE_HDR_ALG_ED448, ed448_pub } };
    cjose_jws_t *jws = NULL;
    for (size_t i = 0; i < sizeof(pub_only) / sizeof(pub_only[0]); i++)
    {
        ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, pub_only[i].alg, &err));
        jws = cjose_jws_sign(pub_only[i].jwk, hdr, plain, sizeof(plain) - 1, &err);
        ck_assert_msg(NULL == jws, "cjose_jws_sign [%s] succeeded with a public key", pub_only[i].alg);
        ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    }

    // verification rejects the wrong key types and curves as well
    jws = cjose_jws_import(JWS_ED25519, strlen(JWS_ED25519), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, ec, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    ck_assert(!cjose_jws_verify(jws, x25519, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    ck_assert(!cjose_jws_verify(jws, ed448, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    cjose_jws_release(jws);

    jws = cjose_jws_import(JWS_ED448, strlen(JWS_ED448), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, ed25519, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    ck_assert(!cjose_jws_verify(jws, x25519, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    cjose_jws_release(jws);

    cjose_header_release(hdr);
    cjose_jwk_release(ed448_pub);
    cjose_jwk_release(pub);
    cjose_jwk_release(ec);
    cjose_jwk_release(x25519);
    cjose_jwk_release(ed448);
    cjose_jwk_release(ed25519);
}
END_TEST

START_TEST(test_cjose_jws_eddsa_deprecated)
{
    cjose_err err;

    // RFC 9864 deprecates the polymorphic "EdDSA" identifier of RFC 8037 in
    // favour of Ed25519 and Ed448, so it is not supported: the RFC 8037
    // appendix A.4 JWS does not even import ...
    static const char *JWS_RFC8037_A4 = "eyJhbGciOiJFZERTQSJ9."
                                        "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
                                        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    ck_assert(NULL == cjose_jws_import(JWS_RFC8037_A4, strlen(JWS_RFC8037_A4), &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    // ... and nothing can be signed with it
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON_OKP_ED25519, strlen(JWK_COMMON_OKP_ED25519), &err);
    ck_assert(NULL != jwk);
    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(NULL != hdr);
    ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, "EdDSA", &err));
    ck_assert(NULL == cjose_jws_sign(jwk, hdr, PLAINTEXT_ED25519, sizeof(PLAINTEXT_ED25519) - 1, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_verify_ed25519_sig_bad_length)
{
    cjose_err err;

    // an Ed25519 signature is exactly 64 octets (RFC 8032 section 5.1.6)
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RFC8037_A2, strlen(JWK_RFC8037_A2), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    // split the compact serialization into the signing input (header.payload.)
    // and the base64url-encoded signature
    const char *last_dot = strrchr(JWS_ED25519, '.');
    ck_assert(NULL != last_dot);
    size_t prefix_len = (last_dot - JWS_ED25519) + 1; // include the trailing '.'
    const char *sig_b64u = last_dot + 1;

    // recover the raw 64-octet signature
    uint8_t *sig_raw = NULL;
    size_t sig_raw_len = 0;
    ck_assert(cjose_base64url_decode(sig_b64u, strlen(sig_b64u), &sig_raw, &sig_raw_len, &err));
    ck_assert_int_eq(64, sig_raw_len);

    // an over-length (65) and an under-length (63) signature must be rejected
    // up front with CJOSE_ERR_INVALID_ARG
    size_t bad_lens[] = { sig_raw_len + 1, sig_raw_len - 1 };
    for (size_t i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++)
    {
        size_t bad_len = bad_lens[i];

        uint8_t *bad_raw = (uint8_t *)cjose_get_alloc()(bad_len);
        ck_assert(NULL != bad_raw);
        memcpy(bad_raw, sig_raw, (bad_len < sig_raw_len) ? bad_len : sig_raw_len);
        if (bad_len > sig_raw_len)
        {
            bad_raw[sig_raw_len] = 0x00; // append a trailing octet
        }

        char *bad_sig_b64u = NULL;
        size_t bad_sig_b64u_len = 0;
        ck_assert(cjose_base64url_encode(bad_raw, bad_len, &bad_sig_b64u, &bad_sig_b64u_len, &err));

        // assemble header.payload. + tampered signature
        size_t cser_len = prefix_len + bad_sig_b64u_len;
        char *cser = (char *)cjose_get_alloc()(cser_len + 1);
        ck_assert(NULL != cser);
        memcpy(cser, JWS_ED25519, prefix_len);
        memcpy(cser + prefix_len, bad_sig_b64u, bad_sig_b64u_len);
        cser[cser_len] = '\0';

        cjose_jws_t *jws_bad = cjose_jws_import(cser, cser_len, &err);
        ck_assert_msg(NULL != jws_bad, "cjose_jws_import failed for bad-length sig: %s", err.message);

        ck_assert_msg(!cjose_jws_verify(jws_bad, jwk, &err), "cjose_jws_verify accepted a %lu-octet Ed25519 signature",
                      (unsigned long)bad_len);
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "expected CJOSE_ERR_INVALID_ARG, got (%i:%s)", err.code, err.message);

        cjose_jws_release(jws_bad);
        cjose_get_dealloc()(cser);
        cjose_get_dealloc()(bad_sig_b64u);
        cjose_get_dealloc()(bad_raw);
    }

    cjose_get_dealloc()(sig_raw);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_self_sign_self_verify_short)
{
    cjose_err err;
    static const uint8_t plain[] = "Setec Astronomy";
    _self_sign_self_verify_all_algs(plain, sizeof(plain) - 1, &err);
}
END_TEST

START_TEST(test_cjose_jws_self_sign_self_verify_empty)
{
    cjose_err err;
    static const uint8_t plain[] = "";
    _self_sign_self_verify_all_algs(plain, sizeof(plain) - 1, &err);
}
END_TEST

START_TEST(test_cjose_jws_self_sign_self_verify_many)
{
    cjose_err err;

    // sign and verify a whole lot of randomly sized payloads
    for (int i = 0; i < 100; ++i)
    {
        size_t len = (size_t)(rand() % 1024) + 1;
        uint8_t *plain = malloc(len);
        ck_assert_msg(RAND_bytes(plain, len) == 1, "RAND_bytes failed");
        plain[len - 1] = 0;
        _self_sign_self_verify_all_algs(plain, len, &err);
        free(plain);
    }
}
END_TEST

START_TEST(test_cjose_jws_sign_with_bad_header)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const uint8_t plain[] = "The mind is everything. What you think you become.";
    size_t plain_len = sizeof(plain) - 1;

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

    // set header for JWS with bad alg
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, "Cayley-Purser", &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // create a JWS
    jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_sign returned bad err.code (%u:%s)", err.code, err.message);

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_sign_with_bad_key)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const uint8_t plain[] = "The mind is everything. What you think you become.";
    size_t plain_len = sizeof(plain) - 1;

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for signing
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"e\": \"AQAB\", "
        "\"n\": "
        "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
        "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
        "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
        "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }",

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err),
                  "cjose_header_set failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // attempt signion with each bad key
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk = cjose_jwk_import(JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk,
                      "cjose_jwk_import failed: "
                      "%s, file: %s, function: %s, line: %ld",
                      err.message, err.file, err.function, err.line);

        jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
        ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "%d cjose_jws_sign returned bad err.code (%u:%s)", i, err.code,
                      err.message);

        cjose_jwk_release(jwk);
    }

    jws = cjose_jws_sign(NULL, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_sign returned bad err.code (%u:%s)", err.code, err.message);

    cjose_header_release(hdr);
}
END_TEST

START_TEST(test_cjose_jws_sign_hmac_with_non_oct_key)
{
    cjose_err err;
    static const uint8_t plain[] = "The mind is everything. What you think you become.";
    size_t plain_len = sizeof(plain) - 1;

    // HS256/HS384/HS512 take an oct key; for any other key type keydata is a
    // key structure, not raw key material, and must not be fed to the HMAC.
    // Before the fix the digest step ran the HMAC over keysize/8 octets of
    // jwk->keydata and only the signing step rejected the key type: an
    // over-read of the (much smaller) EC or RSA key structure that valgrind
    // flags. The P-521 key reads 65 octets from a 16 octet allocation.
    cjose_jwk_t *keys[3] = { NULL, NULL, NULL };
    keys[0] = cjose_jwk_import(JWK_COMMON_EC, strlen(JWK_COMMON_EC), &err);
    keys[1] = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_521, &err);
    keys[2] = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err); // RSA
    static const char *ALGS[] = { CJOSE_HDR_ALG_HS256, CJOSE_HDR_ALG_HS384, CJOSE_HDR_ALG_HS512 };

    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(NULL != hdr);
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
    {
        ck_assert_msg(NULL != keys[k], "creating key %zu failed: %s", k, err.message);
        for (size_t a = 0; a < sizeof(ALGS) / sizeof(ALGS[0]); a++)
        {
            ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, ALGS[a], &err));
            cjose_jws_t *jws = cjose_jws_sign(keys[k], hdr, plain, plain_len, &err);
            ck_assert_msg(NULL == jws, "cjose_jws_sign [%s] accepted a non-oct key (key %zu)", ALGS[a], k);
            ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_sign [%s] returned wrong err.code (%u:%s)", ALGS[a],
                          err.code, err.message);
        }
        cjose_jwk_release(keys[k]);
    }
    cjose_header_release(hdr);
}
END_TEST

START_TEST(test_cjose_jws_sign_with_bad_content)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *JWK
        = "{ \"kty\": \"RSA\", "
          "\"e\": \"AQAB\", "
          "\"n\": "
          "\"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__"
          "VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_"
          "HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_"
          "bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
          "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
          "\"d\": "
          "\"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-"
          "twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-"
          "ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-"
          "duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err), "cjose_header_set failed");

    jws = cjose_jws_sign(jwk, hdr, NULL, 1024, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_sign returned bad err.code (%u:%s)", err.code, err.message);

    jws = cjose_jws_sign(jwk, hdr, NULL, 0, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_sign returned bad err.code (%u:%s)", err.code, err.message);

    cjose_jwk_release(jwk);
    cjose_header_release(hdr);
}
END_TEST

START_TEST(test_cjose_jws_import_export_compare)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // re-export the jws object
    const char *cser = NULL;
    ck_assert_msg(cjose_jws_export(jws, &cser, &err),
                  "re-export of imported JWS faied: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // compare the re-export to the original serialization
    ck_assert_msg(strncmp(JWS_COMMON, cser, strlen(JWS_COMMON)) == 0, "export of imported JWS doesn't match original");

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST

START_TEST(test_cjose_jws_import_invalid_serialization)
{
    cjose_err err;

    static const char *JWS_BAD[]
        = { "eyAiYWxnIjogIkhTMjU2IiB9."
            "SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbS"
            "B0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-"
            "TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_"
            "M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-"
            "eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.x",
            "eyAiYWxnIjogIkhTMjU2IiB9."
            "SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbS"
            "B0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-"
            "TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_"
            "M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-"
            "eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.",
            "eyAiYWxnIjogIkhTMjU2IiB9.."
            "SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbS"
            "B0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-"
            "TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_"
            "M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-"
            "eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
            ".eyAiYWxnIjogIkhTMjU2IiB9."
            "SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbS"
            "B0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-"
            "TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_"
            "M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-"
            "eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
            "AAAA.BBBB",
            "AAAA",
            "",
            "..",
            NULL };

    for (int i = 0; NULL != JWS_BAD[i]; ++i)
    {
        cjose_jws_t *jws = cjose_jws_import(JWS_BAD[i], strlen(JWS_BAD[i]), &err);
        ck_assert_msg(NULL == jws, "cjose_jws_import of bad JWS succeeded");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_import returned wrong err.code (%u:%s)", err.code, err.message);
    }
}
END_TEST

START_TEST(test_cjose_jws_import_get_plain_before_verify)
{
    cjose_err err;

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
                  "cjose_jws_get_plaintext before verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    cjose_jws_release(jws);
}
END_TEST

START_TEST(test_cjose_jws_import_get_plain_after_verify)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // verify the imported jws
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err),
                  "cjose_jws_verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // get plaintext from imported and verified jws
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // compare the verified plaintext to the expected value
    static const uint8_t plain[] = "If you reveal your secrets to the wind, you should not blame the "
                                   "wind for revealing them to the trees. — Kahlil Gibran";
    ck_assert_msg(memcmp(plain, plaintext, sizeof(plain) - 1) == 0, "verified plaintext from JWS doesn't match the original");

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_verify_bad_params)
{
    cjose_err err;

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for signion
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
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // try to verify a NULL jws
    ck_assert_msg(!cjose_jws_verify(NULL, jwk, &err), "cjose_jws_verify succeeded with NULL jws");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);

    // try to verify with a NULL jwk
    ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), "cjose_jws_verify succeeded with NULL jwk");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);

    // try to verify with bad/wrong/unsupported keys
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk_bad = cjose_jwk_import(JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk_bad, "cjose_jwk_import failed");

        ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), "cjose_jws_verify succeeded with bad jwk");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);

        cjose_jwk_release(jwk_bad);
    }

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_verify_hs256)
{
    cjose_err err;

    // https://tools.ietf.org/html/rfc7515#appendix-A.1
    static const char *JWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
                             "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
                             "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const char *JWK = "{ \"kty\": \"oct\", "
                             "\"k\": \"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed");

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const uint8_t PLAINTEXT[] = "{\"iss\":\"joe\",\r\n"
                                       " \"exp\":1300819380,\r\n"
                                       " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(plain_len == sizeof(PLAINTEXT) - 1,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  sizeof(PLAINTEXT) - 1, plain_len);
    ck_assert_msg(memcmp(PLAINTEXT, plain, plain_len) == 0, "verified plaintext does not match signed plaintext");

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST

START_TEST(test_cjose_jws_verify_rs256)
{
    cjose_err err;

    // https://tools.ietf.org/html/rfc7515#appendix-A.2
    static const char *JWS
        = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
          "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_"
          "O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_"
          "eSN9383LcOLn6_dO--xi12jzDwusC-"
          "eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    cjose_jws_t *jws_ok = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws_ok,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const char *JWK
        = "{ \"kty\":\"RSA\","
          "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-"
          "pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-"
          "UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_"
          "h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
          "\"e\":\"AQAB\","
          "\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-"
          "pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_"
          "0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_"
          "RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\","
          "\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_"
          "Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\","
          "\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-"
          "TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\","
          "\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-"
          "FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\","
          "\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-"
          "NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\","
          "\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_"
          "QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err),
                  "cjose_jws_verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws_ok, &plain, &plain_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const uint8_t PLAINTEXT[] = "{\"iss\":\"joe\",\r\n"
                                       " \"exp\":1300819380,\r\n"
                                       " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(plain_len == sizeof(PLAINTEXT) - 1,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  sizeof(PLAINTEXT) - 1, plain_len);
    ck_assert_msg(memcmp(PLAINTEXT, plain, plain_len) == 0, "verified plaintext does not match signed plaintext");

    cjose_jws_release(jws_ok);

    static const char *JWS_TAMPERED_SIG
        = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
          "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_"
          "O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_"
          "eSN9383LcOLn6_dO--xi12jzDwusC-"
          "eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77RW";

    cjose_jws_t *jws_ts = cjose_jws_import(JWS_TAMPERED_SIG, strlen(JWS_TAMPERED_SIG), &err);
    ck_assert_msg(NULL != jws_ts,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_ts, jwk, &err), "cjose_jws_verify succeeded with tampered signature");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);
    cjose_jws_release(jws_ts);

    static const char *JWS_TAMPERED_CONTENT
        = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfq."
          "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_"
          "O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_"
          "eSN9383LcOLn6_dO--xi12jzDwusC-"
          "eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    cjose_jws_t *jws_tc = cjose_jws_import(JWS_TAMPERED_CONTENT, strlen(JWS_TAMPERED_CONTENT), &err);
    ck_assert_msg(NULL != jws_tc,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_tc, jwk, &err), "cjose_jws_verify succeeded with tampered content");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);

    cjose_jws_release(jws_tc);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_verify_rs384)
{
    cjose_err err;

    static const char *JWS = "eyJhbGciOiJSUzM4NCIsImtpZCI6InhrdjNhIn0."
                             "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZmp1cXJDMGlmand0MTVjdEE3dWJEOCIsImlzcyI6Imh0d"
                             "HBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2ODgyODIwNiwiZXhwIjoxNDY4ODI4NTA2LCJub25jZSI6ImpVSmZDeHZ0cG"
                             "NhcDIxWjJBZ3F5ejRJUFVVVWZ3NElrM2JlVks5blpjSjQifQ.Ir1TaYIybDQxubPA1nRKUVaz4X2D6kMjWJpUzC_"
                             "kYiBt8BzdINh5uiCNFXeI9LOVP-eSnwa0vlIg2ZcO1MNyiOQtcK71CKFfwA-1LUMrZtOEYkEQjO8YTAK_Bp1LUQ6QSm_"
                             "jyibUBOHG0mXjdJimwh7Hu8WPOco4RcCXx-LgT55L5ewYReXPC4rNKTm3e3uvwkBs0KcL7CjgMlf6K9AbITwpIHxVFX4s6mlb-"
                             "nlhXZ6pVapkREzvpLxC1JWQIN4Bf4KHv5tMKvjGGvMx-l3FTMQ1ZP-TkuzhN2ZdOE6LynqeNS9uo9qEa4zRM8HLD6-WM6e23y2ph_"
                             "dHgNasVXa2bQ";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const char *JWK
        = "{ \"kty\":\"RSA\","
          "\"n\":\"u-kRzaNkYQXZWtfADCiOC_uGl1Fti_dolgzJgaZdOVpAE4zXbOgfJzm9wQK3IY7K1kFMD7p1bjamWXPOKgKKzqQwdLUOnq-"
          "zgTGga06wR1xGO4luEvRojsYp-eGlgpLCOW2uhzknh6s9JLsfcJ2vzz6LD9omgMY3-JSGS71ECR78yTXAxUnyeoUr_tlFDhDi31uAmXnyP_"
          "O89uqzGn2ZeVFdMPEpdaJCndpuW_zj6jDBFcOlkn6IC_O9UxQH9aEtctkaVdhB5Zw2mP5DWf81f8v8XfScrqn2IVtNcbBWPnHDcRSZPXx1vuN9T083w8_"
          "3wyb3YbTYlcRyvFN703FxsQ\","
          "\"e\":\"AQAB\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err),
                  "cjose_jws_verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const uint8_t PLAINTEXT[]
        = "{\"sub\":\"joe\",\"aud\":\"ac_oic_client\",\"jti\":\"fjuqrC0ifjwt15ctA7ubD8\",\"iss\":\"https:\\/\\/"
          "localhost:9031\",\"iat\":1468828206,\"exp\":1468828506,\"nonce\":\"jUJfCxvtpcap21Z2Agqyz4IPUUUfw4Ik3beVK9nZcJ4\"}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(plain_len == sizeof(PLAINTEXT) - 1,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  sizeof(PLAINTEXT) - 1, plain_len);
    ck_assert_msg(memcmp(PLAINTEXT, plain, plain_len) == 0, "verified plaintext does not match signed plaintext");

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST

START_TEST(test_cjose_jws_verify_ec256)
{
    cjose_err err;

    static const char *JWS = "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0."
                             "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0d"
                             "HBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0"
                             "poSXJ1SkdHSlZVOGpUUGg2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_"
                             "KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3iA";

    cjose_jws_t *jws_ok = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws_ok,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const char *JWK = "{ \"kty\": \"EC\","
                             "\"kid\": \"h4h93\","
                             "\"use\": \"sig\","
                             "\"x\": \"qcZ8jiBDygzf1XMWNN3jS7qT3DDslHOYvaa6XHMxShw\","
                             "\"y\": \"vMcP1OkZsSNaFN6MHrdApLdtLPWo8RnNflgP3DAbcfY\","
                             "\"crv\": \"P-256\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err),
                  "cjose_jws_verify failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws_ok, &plain, &plain_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const uint8_t PLAINTEXT[]
        = "{\"sub\":\"joe\",\"aud\":\"ac_oic_client\",\"jti\":\"detnUiSaSKIiIAotvtg5wW\",\"iss\":\"https:\\/\\/"
          "localhost:9031\",\"iat\":1469030950,\"exp\":1469031250,\"nonce\":\"o35O02-V3JhIruJGGJVU8jTPh6-HJQ83XJfApYLkkdw\"}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(plain_len == sizeof(PLAINTEXT) - 1,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  sizeof(PLAINTEXT) - 1, plain_len);
    ck_assert_msg(memcmp(PLAINTEXT, plain, plain_len) == 0, "verified plaintext does not match signed plaintext");

    cjose_jws_release(jws_ok);

    static const char *JWS_TAMPERED_SIG = "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0."
                                          "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIs"
                                          "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUw"
                                          "LCJub25jZSI6Im8zNU8wMi1WM0poSXJ1SkdHSlZVOGpUUGg2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-"
                                          "h9lPser01eYoK-VMlJoUabKFQ9tT_KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3ia";

    cjose_jws_t *jws_ts = cjose_jws_import(JWS_TAMPERED_SIG, strlen(JWS_TAMPERED_SIG), &err);
    ck_assert_msg(NULL != jws_ts,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_ts, jwk, &err), "cjose_jws_verify succeeded with tampered signature");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);
    cjose_jws_release(jws_ts);

    static const char *JWS_TAMPERED_CONTENT
        = "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0."
          "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhv"
          "c3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0poSXJ1SkdHSlZVOGpUUGG2LUhKUTgzWEpmQXBZ"
          "TGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3iA";

    cjose_jws_t *jws_tc = cjose_jws_import(JWS_TAMPERED_CONTENT, strlen(JWS_TAMPERED_CONTENT), &err);
    ck_assert_msg(NULL != jws_tc,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_tc, jwk, &err), "cjose_jws_verify succeeded with tampered content");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO, "cjose_jws_verify returned wrong err.code (%u:%s)", err.code, err.message);

    cjose_jws_release(jws_tc);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_none)
{
    cjose_err err;

    // https://tools.ietf.org/html/rfc7519#section-6.1
    // Unsecured JWT (alg=none)
    static const char *JWS = "eyJhbGciOiJub25lIn0"
                             ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                             ".";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const char *JWK = "{ \"kty\": \"EC\","
                             "\"kid\": \"h4h93\","
                             "\"use\": \"sig\","
                             "\"x\": \"qcZ8jiBDygzf1XMWNN3jS7qT3DDslHOYvaa6XHMxShw\","
                             "\"y\": \"vMcP1OkZsSNaFN6MHrdApLdtLPWo8RnNflgP3DAbcfY\","
                             "\"crv\": \"P-256\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk,
                  "cjose_jwk_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // get the plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
                  "cjose_jws_get_plaintext failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    static const uint8_t PLAINTEXT[] = "{\"iss\":\"joe\",\r\n"
                                       " \"exp\":1300819380,\r\n"
                                       " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(plain_len == sizeof(PLAINTEXT) - 1,
                  "length of verified plaintext does not match length of original, "
                  "expected: %zu, found: %zu",
                  sizeof(PLAINTEXT) - 1, plain_len);
    ck_assert_msg(memcmp(PLAINTEXT, plain, plain_len) == 0, "verified plaintext does not match signed plaintext");

    // try to verify the unsecured JWS
    ck_assert_msg(!cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify succeeded for unsecured JWT");

    cjose_jws_release(jws);

    jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws,
                  "cjose_jws_import failed: "
                  "%s, file: %s, function: %s, line: %ld",
                  err.message, err.file, err.function, err.line);

    // try to sign the unsecured JWS
    ck_assert_msg(!cjose_jws_sign(jwk, (cjose_header_t *)jws->hdr, PLAINTEXT, sizeof(PLAINTEXT) - 1, &err),
                  "cjose_jws_sign succeeded for unsecured JWT");

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_verify_ps_sig_bad_length)
{
    cjose_err err;
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    // Removing two base64url characters shortens this 2048-bit RSA signature
    // from the required 256 octets to 255 octets.
    size_t compact_len = strlen(JWS_COMMON) - 2;
    char *compact = (char *)cjose_get_alloc()(compact_len + 1);
    ck_assert(NULL != compact);
    memcpy(compact, JWS_COMMON, compact_len);
    compact[compact_len] = '\0';

    cjose_jws_t *jws = cjose_jws_import(compact, compact_len, &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: %s", err.message);
    ck_assert_int_eq(255, jws->sig_len);

    ck_assert_msg(!cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify accepted a short RSA-PSS signature");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "expected CJOSE_ERR_INVALID_ARG, got (%i:%s)", err.code, err.message);

    cjose_jws_release(jws);
    cjose_get_dealloc()(compact);
    cjose_jwk_release(jwk);
}
END_TEST

// regression: the JWS ECDSA signature must be exactly R || S for the key's
// curve; _cjose_jws_verify_sig_ec used sig_len / 2 without a length check,
// so a valid signature with a trailing octet appended still verified
START_TEST(test_cjose_jws_verify_ec_sig_bad_length)
{
    cjose_err err;

    // a valid ES256 (P-256) JWS and its verification key; per RFC 7518 sec 3.4
    // the signature is the fixed-length concatenation R || S (32 + 32 = 64 octets)
    static const char *JWS = "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0."
                             "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0d"
                             "HBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0"
                             "poSXJ1SkdHSlZVOGpUUGg2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_"
                             "KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3iA";

    static const char *JWK = "{ \"kty\": \"EC\","
                             "\"kid\": \"h4h93\","
                             "\"use\": \"sig\","
                             "\"x\": \"qcZ8jiBDygzf1XMWNN3jS7qT3DDslHOYvaa6XHMxShw\","
                             "\"y\": \"vMcP1OkZsSNaFN6MHrdApLdtLPWo8RnNflgP3DAbcfY\","
                             "\"crv\": \"P-256\" }";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    // sanity: the untampered JWS verifies
    cjose_jws_t *jws_ok = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws_ok, "cjose_jws_import failed: %s", err.message);
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err), "cjose_jws_verify failed on valid JWS: %s", err.message);
    cjose_jws_release(jws_ok);

    // split the compact serialization into the signing input (header.payload.)
    // and the base64url-encoded signature
    const char *last_dot = strrchr(JWS, '.');
    ck_assert(NULL != last_dot);
    size_t prefix_len = (last_dot - JWS) + 1; // include the trailing '.'
    const char *sig_b64u = last_dot + 1;

    // recover the raw 64-octet signature
    uint8_t *sig_raw = NULL;
    size_t sig_raw_len = 0;
    ck_assert(cjose_base64url_decode(sig_b64u, strlen(sig_b64u), &sig_raw, &sig_raw_len, &err));
    ck_assert_int_eq(64, sig_raw_len);

    // for both an over-length (65) and an under-length (63) signature, rebuild
    // the serialization and confirm verification rejects it up front with
    // CJOSE_ERR_INVALID_ARG. The over-length case is the malleability the fix
    // closes: previously sig_len/2 dropped the trailing octet and the valid
    // first 64 octets still verified.
    size_t bad_lens[] = { sig_raw_len + 1, sig_raw_len - 1 };
    for (size_t i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++)
    {
        size_t bad_len = bad_lens[i];

        uint8_t *bad_raw = (uint8_t *)cjose_get_alloc()(bad_len);
        ck_assert(NULL != bad_raw);
        memcpy(bad_raw, sig_raw, (bad_len < sig_raw_len) ? bad_len : sig_raw_len);
        if (bad_len > sig_raw_len)
        {
            bad_raw[sig_raw_len] = 0x00; // append a trailing octet
        }

        char *bad_sig_b64u = NULL;
        size_t bad_sig_b64u_len = 0;
        ck_assert(cjose_base64url_encode(bad_raw, bad_len, &bad_sig_b64u, &bad_sig_b64u_len, &err));

        // assemble header.payload. + tampered signature
        size_t cser_len = prefix_len + bad_sig_b64u_len;
        char *cser = (char *)cjose_get_alloc()(cser_len + 1);
        ck_assert(NULL != cser);
        memcpy(cser, JWS, prefix_len);
        memcpy(cser + prefix_len, bad_sig_b64u, bad_sig_b64u_len);
        cser[cser_len] = '\0';

        cjose_jws_t *jws_bad = cjose_jws_import(cser, cser_len, &err);
        ck_assert_msg(NULL != jws_bad, "cjose_jws_import failed for bad-length sig: %s", err.message);

        ck_assert_msg(!cjose_jws_verify(jws_bad, jwk, &err), "cjose_jws_verify accepted a %lu-octet EC signature",
                      (unsigned long)bad_len);
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, "expected CJOSE_ERR_INVALID_ARG, got (%i:%s)", err.code, err.message);

        cjose_jws_release(jws_bad);
        cjose_get_dealloc()(cser);
        cjose_get_dealloc()(bad_sig_b64u);
        cjose_get_dealloc()(bad_raw);
    }

    cjose_get_dealloc()(sig_raw);
    cjose_jwk_release(jwk);
}
END_TEST

Suite *cjose_jws_suite(void)
{
    Suite *suite = suite_create("jws");

    TCase *tc_jws = tcase_create("core");
    tcase_set_timeout(tc_jws, 120.0);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_short);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_empty);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_many);
    tcase_add_test(tc_jws, test_cjose_jws_verify_hs256);
    tcase_add_test(tc_jws, test_cjose_jws_verify_rs256);
    tcase_add_test(tc_jws, test_cjose_jws_verify_rs384);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ec256);
    tcase_add_test(tc_jws, test_cjose_jws_verify_es256k);
    tcase_add_test(tc_jws, test_cjose_jws_es256k_rejects_wrong_curve);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ed25519);
    tcase_add_test(tc_jws, test_cjose_jws_sign_ed25519);
    tcase_add_test(tc_jws, test_cjose_jws_sign_verify_ed448);
    tcase_add_test(tc_jws, test_cjose_jws_ed25519_rejects_wrong_key);
    tcase_add_test(tc_jws, test_cjose_jws_eddsa_deprecated);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ed25519_sig_bad_length);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_header);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_key);
    tcase_add_test(tc_jws, test_cjose_jws_sign_hmac_with_non_oct_key);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_content);
    tcase_add_test(tc_jws, test_cjose_jws_import_export_compare);
    tcase_add_test(tc_jws, test_cjose_jws_import_invalid_serialization);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_before_verify);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_after_verify);
    tcase_add_test(tc_jws, test_cjose_jws_verify_bad_params);
    tcase_add_test(tc_jws, test_cjose_jws_none);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ps_sig_bad_length);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ec_sig_bad_length);
    suite_add_tcase(suite, tc_jws);

    return suite;
}
