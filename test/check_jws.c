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
#include <openssl/rand.h>

// a JWK to be re-used for unit tests
static const char *JWK_COMMON = 
    "{ \"kty\": \"RSA\", "
    "\"e\": \"AQAB\", "
    "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
    "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
    "\"d\": \"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\", "
    "\"p\": \"7X_Hk-tohqmSp8Wv1UcjLw-_DyzYZTmHuXblxWJUk54shbujVU6MQg0_6NIGi0-9Y5_yjiUQMM4wRqrMevYxqMnSzDherN1fI-nWv-PNDrxEFObIFEYJy1vHQe1fqgraoLkgVwyzvrDXtUN_EnSXyALhBdr8vLUnCjkG7-j2UV8\", "
    "\"q\": \"4gPgtf7FT91-FmkkNsrpK0J4Fp8jG1N0GuM30NvS4D715NWOKeuoUi1Ius3yHNdzo9uwLJgY7xJMJlr3ZSmcldwFLBKGVkLctOVLqDWrBLMwD-fPkQVV1FeRfso9bMUcprvSI2RbmIccF02MuLprltmbTdgOJA47_OqjmkHYV-U\", "
    "\"dp\": \"VIJbae8iSoicfsaBQssFYgGgYq36ckp-WShNqmbK4ZwvC4cxH3HLxtUgIKBbY8cEBSctEBdwI227D-pGyJpCIWVvdOu6BJjg-c6Dc9SDavLi5u0X1N73LT2DMZpdqAwkr3wwXclPTFNw7jcOSGrkd29O0t6RgDSVp7WTGlszCtE\", "
    "\"dq\": \"ZWB_5qJENrKO39aBW-Jf-_twihUPVi50oarRWml_iP40pVP01HDTqyiMut2tf6pUQGdF-nqulG2Mopei6Ell5wItf7s_bmnHPYysBuMrtov5PuknfVD7UqeEp25nZuZzF4aflyhovV29B-bM-_8CS0OIGb6TeTC5T5SflY17UNE\", "
    "\"qi\": \"RowmdelfiEBdqfBCSb3yblUKhwJsbyg6HtcugIVOC1yDxD5sZ0cjJPnXj7TJkrC0tICQ50MlPY5F650D9pvACIYnvrGEwsq757Lxg5nqshvuSC-7i1TMkv7_uPBmIxRfzqsnh_hVhxLgSUW1NI6_ncwk9vDQqpkY6qBirgvbyO0\" }";

static const char *JWK_COMMON_OCT =
    "{ \"kty\": \"oct\", "
    "\"k\": \"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }";

static const char *JWK_COMMON_EC =
    "{ \"kty\":\"EC\","
    "\"crv\":\"P-256\","
    "\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\","
    "\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\","
    "\"d\":\"RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM\" }";

// a JWS encrypted with the above JWK_COMMON key
static const char *JWS_COMMON = 
        "eyAiYWxnIjogIlBTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.0YJo4r9gbI2nZ2_1_KLTY3i5SRcZvahRuToavqBvLbm87pN7IYx8YV9kwKQclMW2ASpbEAzKNIJfQ3FycobRwZGtqCI9sRUo0vQvkpb3HIS6HKp3Kvur57J7LcZhz7uNIxzUYNQSg4EWpwhF9FnGng7bmU8qjNPiXCWfQ-n74gopAVzd3KDJ5ai7q66voRc9pCKJVbsaIMHIqcl9OPiMdY5Hz3_PgBalR2632HOdpUlIMvnMOL3EQICvyBwxaYPbhMcCpEc3_4K-sywOGiCSp9KlaLcRq0knZtAT0ynJszaiOwfR-W18PEFLfGclpeR6e_gop9mq69t36wK7KRUjrQ";

// the plaintext payload of the above JWS_COMMON
static const char *PLAIN_COMMON = 
        "If you reveal your secrets to the wind, you should not blame the "
         "wind for revealing them to the trees. — Kahlil Gibran";


static const char *_self_get_jwk_by_alg(const char *alg) {
	if ((strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
		return JWK_COMMON_OCT;
	if ((strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
		return JWK_COMMON_EC;
	return JWK_COMMON;
}

static void _self_sign_self_verify(
        const char *plain1, const char *alg, cjose_err *err)
{
	const char *s_jwk = _self_get_jwk_by_alg(alg);
    cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, strlen(s_jwk), err);

    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // set header for JWS
    cjose_header_t *hdr = cjose_header_new(err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, alg, err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // create the JWS
    size_t plain1_len = strlen(plain1);
    cjose_jws_t *jws1 = cjose_jws_sign(jwk, hdr, plain1, plain1_len, err);
    ck_assert_msg(NULL != jws1, "cjose_jws_sign failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);
    ck_assert(hdr == cjose_jws_get_protected(jws1));

    // get the compact serialization of JWS
    char *compact = NULL;
    ck_assert_msg(
            cjose_jws_export(jws1, &compact, err),
            "cjose_jws_export failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // deserialize the compact representation to a new JWS
    cjose_jws_t *jws2 = cjose_jws_import(compact, strlen(compact), err);
    ck_assert_msg(NULL != jws2, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws2, jwk, err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld",
            err->message, err->file, err->function, err->line);

    // get the verified plaintext
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws2, &plain2, &plain2_len, err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // confirm equal headers
    ck_assert(json_equal(
        cjose_jws_get_protected(jws1),
        cjose_jws_get_protected(jws2)));

    // confirm plain2 == plain1
    ck_assert_msg(
            plain2_len == strlen(plain1),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(plain1), plain2_len);
    ck_assert_msg(
            strncmp(plain1, plain2, plain2_len) == 0,
            "verified plaintext does not match signed plaintext");

    cjose_header_release(hdr);
    cjose_jws_release(jws1);
    cjose_jws_release(jws2);
    cjose_jwk_release(jwk);
}


START_TEST(test_cjose_jws_self_sign_self_verify)
{
    cjose_err err;
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_PS384, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_PS512, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_RS256, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_RS384, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_RS512, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_HS256, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_HS384, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_HS512, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_ES256, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_ES384, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_ES512, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_short)
{
    cjose_err err;
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_PS384, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_PS512, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_RS256, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_RS384, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_RS512, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_HS256, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_HS384, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_HS512, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_ES256, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_ES384, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_ES512, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_empty)
{
    cjose_err err;
    _self_sign_self_verify("", CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_PS384, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_PS512, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_RS256, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_RS384, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_RS512, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_HS256, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_HS384, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_HS512, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_ES256, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_ES384, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_ES512, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_many)
{
    cjose_err err;

    // sign and verify a whole lot of randomly sized payloads
    for (int i = 0; i < 500; ++i)
    {
        size_t len = random() % 1024;
        char *plain = (char *)malloc(len);
        ck_assert_msg(RAND_bytes(plain, len) == 1, "RAND_bytes failed");
        plain[len-1] = 0;
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_PS256, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_PS384, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_PS512, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_RS256, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_RS384, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_RS512, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_HS256, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_HS384, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_HS512, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_ES256, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_ES384, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_ES512, &err);
        free(plain);
    }
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_header)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *plain = 
        "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    static const char *JWK = 
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWS with bad alg
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, "Cayley-Purser", &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // create a JWS
    jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_sign returned bad err.code (%zu:%s)",
                  err.code,
                  err.message);

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_key)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *plain = 
        "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for signing
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }",

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // attempt signion with each bad key
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk = cjose_jwk_import(
                JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

        jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
        ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                      "%d cjose_jws_sign returned bad err.code (%zu:%s)",
                      i,
                      err.code,
                      err.message);

        cjose_jwk_release(jwk);
    }

    jws = cjose_jws_sign(NULL, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_sign returned bad err.code (%zu:%s)",
                  err.code,
                  err.message);

    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_content)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *JWK = 
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"d\": \"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err),
            "cjose_header_set failed");

    jws = cjose_jws_sign(jwk, hdr, NULL, 1024, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_sign returned bad err.code (%zu:%s)",
                  err.code,
                  err.message);

    jws = cjose_jws_sign(jwk, hdr, NULL, 0, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_sign returned bad err.code (%zu:%s)",
                  err.code,
                  err.message);

    cjose_jwk_release(jwk);
    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jws_import_export_compare)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // re-export the jws object
    const char *cser = NULL;
    ck_assert_msg(
            cjose_jws_export(jws, &cser, &err),
            "re-export of imported JWS faied: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // compare the re-export to the original serialization
    ck_assert_msg(
            strncmp(JWS_COMMON, cser, strlen(JWS_COMMON)) == 0,
            "export of imported JWS doesn't match original");

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST


START_TEST(test_cjose_jws_import_invalid_serialization)
{
    cjose_err err;

    static const char *JWS_BAD[] = {
        "eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.x",
        "eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.",
        "eyAiYWxnIjogIkhTMjU2IiB9..SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
        ".eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
        "AAAA.BBBB",
        "AAAA",
        "",
        "..",
        NULL
    };

    for (int i = 0; NULL != JWS_BAD[i]; ++i)
    {
        cjose_jws_t *jws = cjose_jws_import(JWS_BAD[i],strlen(JWS_BAD[i]),&err);
        ck_assert_msg(NULL == jws, "cjose_jws_import of bad JWS succeeded");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                      "cjose_jws_import returned wrong err.code (%zu:%s)",
                      err.code,
                      err.message);
    }
}
END_TEST


START_TEST(test_cjose_jws_import_get_plain_before_verify)
{
    cjose_err err;

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
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
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // decrypt the imported jws
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // get plaintext from imported and verified jws
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // compare the verified plaintext to the expected value
    ck_assert_msg(
            strncmp(PLAIN_COMMON, plaintext, strlen(PLAIN_COMMON)) == 0,
            "verified plaintext from JWS doesn't match the original");

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
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
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
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // try to verify a NULL jws
    ck_assert_msg(!cjose_jws_verify(NULL, jwk, &err), 
            "cjose_jws_verify succeeded with NULL jws");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    // try to verify with a NULL jwk
    ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), 
            "cjose_jws_verify succeeded with NULL jwk");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    // try to verify with bad/wrong/unsupported keys
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk_bad = cjose_jwk_import(
                JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk_bad, "cjose_jwk_import failed");

        ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), 
                "cjose_jws_verify succeeded with bad jwk");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG,
                      "cjose_jws_verify returned wrong err.code (%zu:%s)",
                      err.code,
                      err.message);

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
    static const char *JWS =
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *JWK =
        "{ \"kty\": \"oct\", "
        "\"k\": \"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed");

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *PLAINTEXT =
            "{\"iss\":\"joe\",\r\n"
             " \"exp\":1300819380,\r\n"
             " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(
            plain_len == strlen(PLAINTEXT),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain, plain_len) == 0,
            "verified plaintext does not match signed plaintext: %s", plain);

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST


START_TEST(test_cjose_jws_verify_rs256)
{
    cjose_err err;

    // https://tools.ietf.org/html/rfc7515#appendix-A.2
    static const char *JWS =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    cjose_jws_t *jws_ok = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws_ok, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *JWK =
            "{ \"kty\":\"RSA\","
            "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
            "\"e\":\"AQAB\","
            "\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\","
            "\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\","
            "\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\","
            "\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\","
            "\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\","
            "\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws_ok, &plain, &plain_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *PLAINTEXT =
            "{\"iss\":\"joe\",\r\n"
             " \"exp\":1300819380,\r\n"
             " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(
            plain_len == strlen(PLAINTEXT),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain, plain_len) == 0,
            "verified plaintext does not match signed plaintext: %s", plain);

    cjose_jws_release(jws_ok);

    static const char *JWS_TAMPERED_SIG =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77RW";

    cjose_jws_t *jws_ts = cjose_jws_import(JWS_TAMPERED_SIG, strlen(JWS_TAMPERED_SIG), &err);
    ck_assert_msg(NULL != jws_ts, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_ts, jwk, &err),
            "cjose_jws_verify succeeded with tampered signature");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    static const char *JWS_TAMPERED_CONTENT =
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfq.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    cjose_jws_t *jws_tc = cjose_jws_import(JWS_TAMPERED_CONTENT, strlen(JWS_TAMPERED_CONTENT), &err);
    ck_assert_msg(NULL != jws_tc, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_tc, jwk, &err),
            "cjose_jws_verify succeeded with tampered content");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    cjose_jwk_release(jwk);
}
END_TEST


START_TEST(test_cjose_jws_verify_rs384)
{
    cjose_err err;

    static const char *JWS =
            "eyJhbGciOiJSUzM4NCIsImtpZCI6InhrdjNhIn0.eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZmp1cXJDMGlmand0MTVjdEE3dWJEOCIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2ODgyODIwNiwiZXhwIjoxNDY4ODI4NTA2LCJub25jZSI6ImpVSmZDeHZ0cGNhcDIxWjJBZ3F5ejRJUFVVVWZ3NElrM2JlVks5blpjSjQifQ.Ir1TaYIybDQxubPA1nRKUVaz4X2D6kMjWJpUzC_kYiBt8BzdINh5uiCNFXeI9LOVP-eSnwa0vlIg2ZcO1MNyiOQtcK71CKFfwA-1LUMrZtOEYkEQjO8YTAK_Bp1LUQ6QSm_jyibUBOHG0mXjdJimwh7Hu8WPOco4RcCXx-LgT55L5ewYReXPC4rNKTm3e3uvwkBs0KcL7CjgMlf6K9AbITwpIHxVFX4s6mlb-nlhXZ6pVapkREzvpLxC1JWQIN4Bf4KHv5tMKvjGGvMx-l3FTMQ1ZP-TkuzhN2ZdOE6LynqeNS9uo9qEa4zRM8HLD6-WM6e23y2ph_dHgNasVXa2bQ";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *JWK =
            "{ \"kty\":\"RSA\","
            "\"n\":\"u-kRzaNkYQXZWtfADCiOC_uGl1Fti_dolgzJgaZdOVpAE4zXbOgfJzm9wQK3IY7K1kFMD7p1bjamWXPOKgKKzqQwdLUOnq-zgTGga06wR1xGO4luEvRojsYp-eGlgpLCOW2uhzknh6s9JLsfcJ2vzz6LD9omgMY3-JSGS71ECR78yTXAxUnyeoUr_tlFDhDi31uAmXnyP_O89uqzGn2ZeVFdMPEpdaJCndpuW_zj6jDBFcOlkn6IC_O9UxQH9aEtctkaVdhB5Zw2mP5DWf81f8v8XfScrqn2IVtNcbBWPnHDcRSZPXx1vuN9T083w8_3wyb3YbTYlcRyvFN703FxsQ\","
            "\"e\":\"AQAB\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *PLAINTEXT =
            "{\"sub\":\"joe\",\"aud\":\"ac_oic_client\",\"jti\":\"fjuqrC0ifjwt15ctA7ubD8\",\"iss\":\"https:\\/\\/localhost:9031\",\"iat\":1468828206,\"exp\":1468828506,\"nonce\":\"jUJfCxvtpcap21Z2Agqyz4IPUUUfw4Ik3beVK9nZcJ4\"}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(
            plain_len == strlen(PLAINTEXT),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain, plain_len) == 0,
            "verified plaintext does not match signed plaintext: %s", plain);

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST

START_TEST(test_cjose_jws_verify_ec256)
{
    cjose_err err;

    static const char *JWS =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0.eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0poSXJ1SkdHSlZVOGpUUGg2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3iA";

    cjose_jws_t *jws_ok = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws_ok, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *JWK =
            "{ \"kty\": \"EC\","
            "\"kid\": \"h4h93\","
            "\"use\": \"sig\","
            "\"x\": \"qcZ8jiBDygzf1XMWNN3jS7qT3DDslHOYvaa6XHMxShw\","
            "\"y\": \"vMcP1OkZsSNaFN6MHrdApLdtLPWo8RnNflgP3DAbcfY\","
            "\"crv\": \"P-256\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws_ok, jwk, &err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // get the verified plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws_ok, &plain, &plain_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *PLAINTEXT =
            "{\"sub\":\"joe\",\"aud\":\"ac_oic_client\",\"jti\":\"detnUiSaSKIiIAotvtg5wW\",\"iss\":\"https:\\/\\/localhost:9031\",\"iat\":1469030950,\"exp\":1469031250,\"nonce\":\"o35O02-V3JhIruJGGJVU8jTPh6-HJQ83XJfApYLkkdw\"}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(
            plain_len == strlen(PLAINTEXT),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain, plain_len) == 0,
            "verified plaintext does not match signed plaintext: %s", plain);

    cjose_jws_release(jws_ok);

    static const char *JWS_TAMPERED_SIG =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0.eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0poSXJ1SkdHSlZVOGpUUGg2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3ia";

    cjose_jws_t *jws_ts = cjose_jws_import(JWS_TAMPERED_SIG, strlen(JWS_TAMPERED_SIG), &err);
    ck_assert_msg(NULL != jws_ts, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_ts, jwk, &err),
            "cjose_jws_verify succeeded with tampered signature");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    static const char *JWS_TAMPERED_CONTENT =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Img0aDkzIn0.eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoiZGV0blVpU2FTS0lpSUFvdHZ0ZzV3VyIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2OTAzMDk1MCwiZXhwIjoxNDY5MDMxMjUwLCJub25jZSI6Im8zNU8wMi1WM0poSXJ1SkdHSlZVOGpUUGG2LUhKUTgzWEpmQXBZTGtrZHcifQ.o9bb_yW6-h9lPser01eYoK-VMlJoUabKFQ9tT_KdgMHlqRqTa4isqFqXllViDdUIQoHGMMP7Qms565YKSCS3iA";

    cjose_jws_t *jws_tc = cjose_jws_import(JWS_TAMPERED_CONTENT, strlen(JWS_TAMPERED_CONTENT), &err);
    ck_assert_msg(NULL != jws_tc, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    ck_assert_msg(!cjose_jws_verify(jws_tc, jwk, &err),
            "cjose_jws_verify succeeded with tampered content");
    ck_assert_msg(err.code == CJOSE_ERR_CRYPTO,
                  "cjose_jws_verify returned wrong err.code (%zu:%s)",
                  err.code,
                  err.message);

    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jws_none)
{
    cjose_err err;

    // https://tools.ietf.org/html/rfc7519#section-6.1
    // Unsecured JWT (alg=none)
    static const char *JWS =
            "eyJhbGciOiJub25lIn0"
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            ".";

    cjose_jws_t *jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *JWK =
            "{ \"kty\": \"EC\","
            "\"kid\": \"h4h93\","
            "\"use\": \"sig\","
            "\"x\": \"qcZ8jiBDygzf1XMWNN3jS7qT3DDslHOYvaa6XHMxShw\","
            "\"y\": \"vMcP1OkZsSNaFN6MHrdApLdtLPWo8RnNflgP3DAbcfY\","
            "\"crv\": \"P-256\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // get the plaintext
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plain, &plain_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    static const char *PLAINTEXT =
            "{\"iss\":\"joe\",\r\n"
             " \"exp\":1300819380,\r\n"
             " \"http://example.com/is_root\":true}";

    // confirm plain == PLAINTEXT
    ck_assert_msg(
            plain_len == strlen(PLAINTEXT),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain, plain_len) == 0,
            "verified plaintext does not match signed plaintext: %s", plain);

    // try to verify the unsecured JWS
    ck_assert_msg(!cjose_jws_verify(jws, jwk, &err),
            "cjose_jws_verify succeeded for unsecured JWT");


    jws = cjose_jws_import(JWS, strlen(JWS), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld",
            err.message, err.file, err.function, err.line);

    // try to sign the unsecured JWS
    ck_assert_msg(!cjose_jws_sign(jwk, jws->hdr, PLAINTEXT, strlen(PLAINTEXT), &err),
            "cjose_jws_sign succeeded for unsecured JWT");

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST

Suite *cjose_jws_suite()
{
    Suite *suite = suite_create("jws");

    TCase *tc_jws = tcase_create("core");
    tcase_set_timeout(tc_jws, 60.0);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_short);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_empty);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_many);
    tcase_add_test(tc_jws, test_cjose_jws_verify_hs256);
    tcase_add_test(tc_jws, test_cjose_jws_verify_rs256);
    tcase_add_test(tc_jws, test_cjose_jws_verify_rs384);
    tcase_add_test(tc_jws, test_cjose_jws_verify_ec256);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_header);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_key);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_content);
    tcase_add_test(tc_jws, test_cjose_jws_import_export_compare);
    tcase_add_test(tc_jws, test_cjose_jws_import_invalid_serialization);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_before_verify);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_after_verify);
    tcase_add_test(tc_jws, test_cjose_jws_verify_bad_params);
    tcase_add_test(tc_jws, test_cjose_jws_none);
    suite_add_tcase(suite, tc_jws);

    return suite;
}
