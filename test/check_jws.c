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
    for (size_t i = 0; i < 100; ++i)
    {
        size_t len = (size_t)(rand() % 1024) + 1;
        uint8_t *plain = malloc(len);
        ck_assert_msg(RAND_bytes_ex(NULL, plain, len, 0) == 1, "RAND_bytes failed");
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

// RFC 7515 section 4.1.11: cjose implements no extension, so a JWS whose
// header carries a "crit" list is refused, when signing and when verifying
START_TEST(test_cjose_jws_crit_refused)
{
    cjose_err err;
    static const uint8_t plain[] = "Setec Astronomy";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON_OCT, strlen(JWK_COMMON_OCT), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: %s", err.message);

    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_HS256, &err));
    ck_assert(cjose_header_set(hdr, CJOSE_HDR_CTY, "JWT", &err));
    ck_assert(cjose_header_set_raw(hdr, "crit", "[\"cty\"]", &err));
    ck_assert_msg(NULL == cjose_jws_sign(jwk, hdr, plain, sizeof(plain) - 1, &err), "cjose_jws_sign accepted a crit list");
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    // the same JWS, made without the list and given one afterwards, is refused
    // when it is imported
    memset(&err, 0, sizeof(err));
    json_object_del((json_t *)hdr, "crit");
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, plain, sizeof(plain) - 1, &err);
    ck_assert_msg(NULL != jws, "cjose_jws_sign failed: %s", err.message);
    const char *compact = NULL;
    ck_assert(cjose_jws_export(jws, &compact, &err));

    json_t *header = json_pack("{s:s,s:s,s:[s]}", "alg", "HS256", "cty", "JWT", "crit", "cty");
    char *header_str = json_dumps(header, JSON_COMPACT);
    char *header_b64u = NULL;
    size_t header_b64u_len = 0;
    ck_assert(cjose_base64url_encode((const uint8_t *)header_str, strlen(header_str), &header_b64u, &header_b64u_len, &err));
    const char *rest = strchr(compact, '.');
    char *tampered = malloc(header_b64u_len + strlen(rest) + 1);
    ck_assert(NULL != tampered);
    memcpy(tampered, header_b64u, header_b64u_len);
    strcpy(tampered + header_b64u_len, rest);

    memset(&err, 0, sizeof(err));
    ck_assert_msg(NULL == cjose_jws_import(tampered, strlen(tampered), &err), "cjose_jws_import accepted a crit list");
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    free(tampered);
    cjose_get_dealloc()(header_b64u);
    cjose_get_dealloc()(header_str);
    json_decref(header);
    cjose_jws_release(jws);
    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST

#ifdef HAVE_ML_DSA

// The ML-DSA examples of RFC 9964 Appendix A.1: the JWS and the JWKs it
// verifies and signs under, for each of the three algorithms. The payload is
// the same sentence in all three. Each JWS runs past the 4095 characters C17
// guarantees for a string literal, so it is kept in pieces and joined below.

static const char *JWS_ML_DSA_44_PARTS[]
    = { "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0."
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc"
        "7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHN"
        "L2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0"
        "z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-"
        "EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al"
        "04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2wo"
        "WUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujX"
        "VJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9"
        "WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39"
        "lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJ"
        "jOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8"
        "aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQV"
        "lYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120"
        "g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8"
        "ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMh"
        "Jthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRv"
        "PElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khO"
        "qwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw"
        "_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_D"
        "TiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZi"
        "KoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrx"
        "f94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm"
        "1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCz"
        "v53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1"
        "UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv7"
        "44VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOA"
        "BenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20Dw"
        "DBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4Br"
        "lNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKD"
        "TRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0d"
        "iR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Y"
        "o3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5"
        "h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaO"
        "Kgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVpl"
        "cHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIfMEQ",
        NULL };

static const char *JWK_ML_DSA_44_PUBLIC
    = "{\"kid\":\"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"unH59k"
      "4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lh"
      "uk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls"
      "0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQz"
      "qPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z"
      "_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QG"
      "nDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu"
      "9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7"
      "GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJe"
      "riq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGc"
      "cSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWX"
      "DbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNB"
      "AZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrR"
      "uCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBY"
      "JWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5"
      "nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkL"
      "RJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu6"
      "75ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rx"
      "rid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7"
      "gEWzw4MFRrndjbDQ\"}";

static const char *JWK_ML_DSA_44_PRIVATE
    = "{\"kid\":\"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"unH59k"
      "4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lh"
      "uk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls"
      "0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQz"
      "qPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z"
      "_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QG"
      "nDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu"
      "9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7"
      "GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJe"
      "riq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGc"
      "cSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWX"
      "DbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNB"
      "AZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrR"
      "uCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBY"
      "JWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5"
      "nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkL"
      "RJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu6"
      "75ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rx"
      "rid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7"
      "gEWzw4MFRrndjbDQ\",\"priv\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";

static const char *JWS_ML_DSA_65_PARTS[]
    = { "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0."
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfR"
        "o4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGi"
        "NLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0"
        "-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKP"
        "Hu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjt"
        "GOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oR"
        "nll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnx"
        "svBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQ"
        "NcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFN"
        "fMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJzn"
        "QAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06Exdz"
        "BhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMN"
        "T7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7"
        "kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302U"
        "o0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA"
        "9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDj"
        "t7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaM"
        "yBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ4"
        "8nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoW"
        "Tr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGN"
        "HpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwM"
        "ArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstm"
        "SXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZC"
        "Hd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp"
        "90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gt"
        "L-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3c"
        "UW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDp"
        "hbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiI"
        "dyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRd"
        "xCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAcl"
        "xcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOX"
        "PATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8i"
        "Yyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV2"
        "1QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQ"
        "oszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9"
        "_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9s"
        "QVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJ"
        "J3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_"
        "iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6",
        "jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZ"
        "ybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZl"
        "jCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoB"
        "HGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zor"
        "TWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMf"
        "z8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0f"
        "nrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4i"
        "O4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVHCUv",
        NULL };

static const char *JWK_ML_DSA_65_PUBLIC
    = "{\"kid\":\"Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-65\",\"pub\":\"QksvJn"
      "5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9Nm"
      "fmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb"
      "0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBk"
      "s23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIu"
      "rcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-"
      "Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLB"
      "B3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51p"
      "ljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1"
      "FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7w"
      "ZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjx"
      "clmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUd"
      "m-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-"
      "tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJU"
      "UBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk"
      "6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UN"
      "wwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJq"
      "ZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-"
      "Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-"
      "ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD"
      "4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFY"
      "HhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-"
      "qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0B"
      "ZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8"
      "xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJ"
      "bXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTE"
      "yRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1M"
      "EZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsy"
      "W1Juo\"}";

static const char *JWK_ML_DSA_65_PRIVATE
    = "{\"kid\":\"Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-65\",\"pub\":\"QksvJn"
      "5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9Nm"
      "fmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb"
      "0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBk"
      "s23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIu"
      "rcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-"
      "Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLB"
      "B3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51p"
      "ljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1"
      "FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7w"
      "ZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjx"
      "clmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUd"
      "m-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-"
      "tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJU"
      "UBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk"
      "6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UN"
      "wwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJq"
      "ZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-"
      "Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-"
      "ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD"
      "4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFY"
      "HhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-"
      "qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0B"
      "ZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8"
      "xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJ"
      "bXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTE"
      "yRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1M"
      "EZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsy"
      "W1Juo\",\"priv\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";

static const char *JWS_ML_DSA_87_PARTS[]
    = { "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0."
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXU"
        "Vq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0"
        "-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJ"
        "DBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQ"
        "pyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrA"
        "NbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpi"
        "AAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2"
        "xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFy"
        "N3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9"
        "WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYW"
        "MI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY"
        "7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vt"
        "ZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlA"
        "X56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPm"
        "unUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHm"
        "FUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_V"
        "WvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1"
        "BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAr"
        "aTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXr"
        "upgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91Vq"
        "JYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4"
        "_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV"
        "8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NX"
        "p06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFp"
        "VCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A"
        "4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn"
        "0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0"
        "JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04"
        "jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJ"
        "ZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-"
        "idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw"
        "_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7"
        "hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8"
        "Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384Sok"
        "PX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLt"
        "hfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_x"
        "xUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCi"
        "q29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP"
        "2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSl",
        "XYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZ"
        "Wz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sf"
        "AERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65"
        "xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43Tfy"
        "YhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIs"
        "cdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z"
        "44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS9"
        "1KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B"
        "_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThq"
        "OEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6"
        "VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2St"
        "BdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6"
        "Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuV"
        "fv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb4"
        "7LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplU"
        "qsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4"
        "qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGz"
        "EVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2"
        "ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquE"
        "t7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0B"
        "dckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10Wi"
        "L_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEc"
        "uVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIU"
        "muDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0q"
        "Ta4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaA"
        "gaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAl"
        "Kzg7Qw",
        NULL };

static const char *JWK_ML_DSA_87_PUBLIC
    = "{\"kid\":\"tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-87\",\"pub\":\"5F_8jM"
      "c9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4"
      "x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73en"
      "vj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm"
      "9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6byl"
      "PM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXov"
      "da4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAg"
      "kE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61Cy"
      "yrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9"
      "HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuD"
      "xMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-"
      "r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUf"
      "rJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x"
      "8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8ms"
      "b8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOt"
      "e0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbC"
      "H2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9"
      "Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPk"
      "y75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHU"
      "ryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjf"
      "IC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g81"
      "7bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHls"
      "b8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DN"
      "EgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F"
      "4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bem"
      "WqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_"
      "4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0c"
      "BIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwU"
      "emXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaC"
      "PoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT"
      "2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0o"
      "thfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo"
      "2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU"
      "0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxm"
      "k4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFh"
      "M9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_n"
      "uLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj\"}";

static const char *JWK_ML_DSA_87_PRIVATE
    = "{\"kid\":\"tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU\",\"kty\":\"AKP\",\"alg\":\"ML-DSA-87\",\"pub\":\"5F_8jM"
      "c9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4"
      "x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73en"
      "vj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm"
      "9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6byl"
      "PM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXov"
      "da4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAg"
      "kE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61Cy"
      "yrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9"
      "HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuD"
      "xMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-"
      "r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUf"
      "rJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x"
      "8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8ms"
      "b8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOt"
      "e0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbC"
      "H2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9"
      "Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPk"
      "y75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHU"
      "ryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjf"
      "IC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g81"
      "7bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHls"
      "b8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DN"
      "EgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F"
      "4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bem"
      "WqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_"
      "4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0c"
      "BIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwU"
      "emXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaC"
      "PoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT"
      "2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0o"
      "thfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo"
      "2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU"
      "0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxm"
      "k4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFh"
      "M9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_n"
      "uLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj\",\"pri"
      "v\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";

// "It\u2019s a dangerous business, Frodo, going out your door." in UTF-8
static const char *ML_DSA_PLAINTEXT = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door.";

// joins a NULL-terminated list of pieces into one string the caller frees
static char *_ml_dsa_join(const char **parts)
{
    size_t total = 0;
    for (size_t i = 0; NULL != parts[i]; i++)
    {
        total += strlen(parts[i]);
    }
    char *out = malloc(total + 1);
    ck_assert(NULL != out);
    out[0] = '\0';
    for (size_t i = 0; NULL != parts[i]; i++)
    {
        strcat(out, parts[i]);
    }
    return out;
}

#endif // HAVE_ML_DSA

#ifdef HAVE_ML_DSA

static const struct
{
    const char **jws_parts;
    const char **jwk_public;
    const char **jwk_private;
    const char *alg;
} ML_DSA_VECTORS[] = {
    { JWS_ML_DSA_44_PARTS, &JWK_ML_DSA_44_PUBLIC, &JWK_ML_DSA_44_PRIVATE, CJOSE_HDR_ALG_ML_DSA_44 },
    { JWS_ML_DSA_65_PARTS, &JWK_ML_DSA_65_PUBLIC, &JWK_ML_DSA_65_PRIVATE, CJOSE_HDR_ALG_ML_DSA_65 },
    { JWS_ML_DSA_87_PARTS, &JWK_ML_DSA_87_PUBLIC, &JWK_ML_DSA_87_PRIVATE, CJOSE_HDR_ALG_ML_DSA_87 },
};

START_TEST(test_cjose_jws_ml_dsa_rfc9964_vectors)
{
    cjose_err err;

    for (size_t i = 0; i < sizeof(ML_DSA_VECTORS) / sizeof(ML_DSA_VECTORS[0]); i++)
    {
        char *jws_str = _ml_dsa_join(ML_DSA_VECTORS[i].jws_parts);
        const char *jwk_str = *ML_DSA_VECTORS[i].jwk_public;

        cjose_jwk_t *jwk = cjose_jwk_import(jwk_str, strlen(jwk_str), &err);
        ck_assert_msg(NULL != jwk, "cjose_jwk_import failed (%zu): %s", i, err.message);

        cjose_jws_t *jws = cjose_jws_import(jws_str, strlen(jws_str), &err);
        ck_assert_msg(NULL != jws, "cjose_jws_import failed (%zu): %s", i, err.message);
        ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "the RFC 9964 %s JWS did not verify: %s", ML_DSA_VECTORS[i].alg,
                      err.message);

        uint8_t *plain = NULL;
        size_t plain_len = 0;
        ck_assert(cjose_jws_get_plaintext(jws, &plain, &plain_len, &err));
        ck_assert_int_eq(strlen(ML_DSA_PLAINTEXT), plain_len);
        ck_assert(0 == memcmp(ML_DSA_PLAINTEXT, plain, plain_len));

        cjose_jws_release(jws);
        cjose_jwk_release(jwk);
        free(jws_str);
    }
}
END_TEST

START_TEST(test_cjose_jws_ml_dsa_self_sign_self_verify)
{
    cjose_err err;
    static const uint8_t plain[] = "Setec Astronomy";

    for (size_t i = 0; i < sizeof(ML_DSA_VECTORS) / sizeof(ML_DSA_VECTORS[0]); i++)
    {
        const char *jwk_str = *ML_DSA_VECTORS[i].jwk_private;
        cjose_jwk_t *jwk = cjose_jwk_import(jwk_str, strlen(jwk_str), &err);
        ck_assert_msg(NULL != jwk, "cjose_jwk_import failed (%zu): %s", i, err.message);

        cjose_header_t *hdr = cjose_header_new(&err);
        ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, ML_DSA_VECTORS[i].alg, &err));

        cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, plain, sizeof(plain) - 1, &err);
        ck_assert_msg(NULL != jws, "cjose_jws_sign failed for %s: %s", ML_DSA_VECTORS[i].alg, err.message);

        const char *compact = NULL;
        ck_assert(cjose_jws_export(jws, &compact, &err));

        cjose_jws_t *imported = cjose_jws_import(compact, strlen(compact), &err);
        ck_assert_msg(NULL != imported, "cjose_jws_import failed: %s", err.message);
        ck_assert_msg(cjose_jws_verify(imported, jwk, &err), "cjose_jws_verify failed for %s: %s", ML_DSA_VECTORS[i].alg,
                      err.message);

        uint8_t *out = NULL;
        size_t out_len = 0;
        ck_assert(cjose_jws_get_plaintext(imported, &out, &out_len, &err));
        ck_assert_int_eq(sizeof(plain) - 1, out_len);
        ck_assert(0 == memcmp(plain, out, out_len));

        cjose_jws_release(imported);
        cjose_jws_release(jws);
        cjose_header_release(hdr);
        cjose_jwk_release(jwk);
    }
}
END_TEST

START_TEST(test_cjose_jws_ml_dsa_bad_params)
{
    cjose_err err;
    static const uint8_t plain[] = "Setec Astronomy";

    // a public-only key cannot sign: EVP_DigestSignInit succeeds on one, so
    // the JWK's own key material is what has to refuse it
    cjose_jwk_t *pub = cjose_jwk_import(JWK_ML_DSA_44_PUBLIC, strlen(JWK_ML_DSA_44_PUBLIC), &err);
    ck_assert(NULL != pub);
    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ML_DSA_44, &err));
    ck_assert(NULL == cjose_jws_sign(pub, hdr, plain, sizeof(plain) - 1, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    // the "alg" header has to be the algorithm the key belongs to
    cjose_jwk_t *priv44 = cjose_jwk_import(JWK_ML_DSA_44_PRIVATE, strlen(JWK_ML_DSA_44_PRIVATE), &err);
    ck_assert(NULL != priv44);
    cjose_header_t *hdr65 = cjose_header_new(&err);
    ck_assert(cjose_header_set(hdr65, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ML_DSA_65, &err));
    ck_assert(NULL == cjose_jws_sign(priv44, hdr65, plain, sizeof(plain) - 1, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    // an ML-DSA header over a key of another type is refused too
    cjose_jwk_t *oct = cjose_jwk_import(JWK_COMMON_OCT, strlen(JWK_COMMON_OCT), &err);
    ck_assert(NULL != oct);
    ck_assert(NULL == cjose_jws_sign(oct, hdr, plain, sizeof(plain) - 1, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);

    // the RFC's own JWS does not verify under a key of another algorithm ...
    cjose_jwk_t *pub87 = cjose_jwk_import(JWK_ML_DSA_87_PUBLIC, strlen(JWK_ML_DSA_87_PUBLIC), &err);
    ck_assert(NULL != pub87);
    char *vec44_early = _ml_dsa_join(JWS_ML_DSA_44_PARTS);
    cjose_jws_t *jws = cjose_jws_import(vec44_early, strlen(vec44_early), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, pub87, &err));
    cjose_jws_release(jws);
    free(vec44_early);

    // ... nor with a signature of the wrong length, which is refused as an
    // invalid argument before OpenSSL sees it
    char *vector44 = _ml_dsa_join(JWS_ML_DSA_44_PARTS);
    const char *last_dot = strrchr(vector44, '.');
    ck_assert(NULL != last_dot);
    const size_t prefix_len = (size_t)(last_dot - vector44) + 1;
    char *truncated = malloc(prefix_len + 16 + 1);
    ck_assert(NULL != truncated);
    memcpy(truncated, vector44, prefix_len);
    // 12 base64url characters decode to 9 octets, never the algorithm's size
    memcpy(truncated + prefix_len, "AAAAAAAAAAAA", 12);
    truncated[prefix_len + 12] = '\0';
    jws = cjose_jws_import(truncated, strlen(truncated), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, pub, &err));
    ck_assert_int_eq(CJOSE_ERR_INVALID_ARG, err.code);
    cjose_jws_release(jws);
    free(truncated);

    // ... nor with one of the right length whose last character was changed
    const size_t jws_len = strlen(vector44);
    char *flipped = malloc(jws_len + 1);
    ck_assert(NULL != flipped);
    memcpy(flipped, vector44, jws_len + 1);
    flipped[jws_len - 1] = (flipped[jws_len - 1] == 'A') ? 'B' : 'A';
    jws = cjose_jws_import(flipped, strlen(flipped), &err);
    ck_assert(NULL != jws);
    ck_assert(!cjose_jws_verify(jws, pub, &err));
    cjose_jws_release(jws);
    free(flipped);

    free(vector44);
    cjose_jwk_release(pub87);
    cjose_jwk_release(oct);
    cjose_jwk_release(priv44);
    cjose_jwk_release(pub);
    cjose_header_release(hdr65);
    cjose_header_release(hdr);
}
END_TEST

#endif // HAVE_ML_DSA

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
    tcase_add_test(tc_jws, test_cjose_jws_crit_refused);
#ifdef HAVE_ML_DSA
    tcase_add_test(tc_jws, test_cjose_jws_ml_dsa_rfc9964_vectors);
    tcase_add_test(tc_jws, test_cjose_jws_ml_dsa_self_sign_self_verify);
    tcase_add_test(tc_jws, test_cjose_jws_ml_dsa_bad_params);
#endif
    suite_add_tcase(suite, tc_jws);

    return suite;
}
