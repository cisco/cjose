/*!
 *
 */

#include "check_cjose.h"

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include "include/jwk_int.h"
#include "include/jwe_int.h"
#include "include/header_int.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

START_TEST(test_cjose_header_new_release)
{
    cjose_err err;

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    cjose_header_release(header);
}
END_TEST

START_TEST(test_cjose_header_retain_release)
{
    cjose_err err;

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    header = cjose_header_retain(header);
    ck_assert_msg(NULL != header, "cjose_header_retain failed");

    cjose_header_release(header);

    cjose_header_release(header);
}
END_TEST

START_TEST(test_cjose_header_set_get)
{
    cjose_err err;
    bool result;
    const char *alg_get, *alg_set = "RSA-OAEP";
    const char *enc_get, *enc_set = "A256GCM";

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    result = cjose_header_set(header, CJOSE_HDR_ALG, alg_set, &err);
    ck_assert_msg(result, "cjose_header_set failed to set ALG");

    result = cjose_header_set(header, CJOSE_HDR_ENC, enc_set, &err);
    ck_assert_msg(result, "cjose_header_set failed to set ENC");

    alg_get = cjose_header_get(header, CJOSE_HDR_ALG, &err);
    ck_assert_msg(NULL != alg_get, "cjose_header_get failed to get ALG");

    enc_get = cjose_header_get(header, CJOSE_HDR_ENC, &err);
    ck_assert_msg(NULL != enc_get, "cjose_header_get failed to get ENC");

    ck_assert_msg(!strcmp(alg_set, alg_get), "cjose_header_get failed, "
                                             "expected: %s, found: %s",
                  ((alg_set) ? alg_set : "null"), ((alg_get) ? alg_get : "null"));

    ck_assert_msg(!strcmp(enc_set, enc_get), "cjose_header_get failed, "
                                             "expected: %s, found: %s",
                  ((enc_set) ? enc_set : "null"), ((enc_get) ? enc_get : "null"));

    cjose_header_release(header);
}
END_TEST

START_TEST(test_cjose_header_set_get_raw)
{
    cjose_err err;
    bool result;
    char *epk_get;
    const char *epk_set = "{\"kty\":\"EC\","
                          "\"crv\":\"P-256\","
                          "\"x\":\"_XNXAUbQMEboZR7uG-SqA8pQPWj-BCjaEx3LyXdX1lA\","
                          "\"y\":\"8o4GHhoWsWI40dK1LGGR7X9tCoOt-lcc5Sqw2yD8Gvw\"}";

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    result = cjose_header_set_raw(header, CJOSE_HDR_EPK, epk_set, &err);
    ck_assert_msg(result, "cjose_header_set_raw failed to set EPK");

    epk_get = cjose_header_get_raw(header, CJOSE_HDR_EPK, &err);
    ck_assert_msg(NULL != epk_get, "cjose_header_get_raw failed to get EPK");

    ck_assert_msg(!strcmp(epk_set, epk_get), "cjose_header_get_raw failed, "
                                             "expected: %s, found %s",
                  ((epk_set) ? epk_set : "null"), ((epk_get) ? epk_get : "null"));

    // cjose_header_get_raw returns a json_dumps() result owned by the caller
    cjose_get_dealloc()(epk_get);
    cjose_header_release(header);
}
END_TEST

// regression: RFC 7515 section 4.1.11 requires a "crit" list, if present, to
// be non-empty; _cjose_header_validate_crit accepted an empty list
START_TEST(test_cjose_header_validate_crit)
{
    cjose_err err;
    static const char *const supported[] = { "alg", "cty" };
    const size_t supported_len = sizeof(supported) / sizeof(supported[0]);

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    // no "crit" header at all is fine
    ck_assert(_cjose_header_validate_crit(header, supported, supported_len, &err));

    // a supported extension is fine
    ck_assert(cjose_header_set_raw(header, "crit", "[\"cty\"]", &err));
    ck_assert(_cjose_header_validate_crit(header, supported, supported_len, &err));

    // an unsupported extension is rejected
    ck_assert(cjose_header_set_raw(header, "crit", "[\"exp\"]", &err));
    ck_assert(!_cjose_header_validate_crit(header, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // a non-array value is rejected
    ck_assert(cjose_header_set(header, "crit", "cty", &err));
    ck_assert(!_cjose_header_validate_crit(header, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // an empty list is rejected (RFC 7515 section 4.1.11)
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set_raw(header, "crit", "[]", &err));
    ck_assert(!_cjose_header_validate_crit(header, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    cjose_header_release(header);
}
END_TEST

Suite *cjose_header_suite(void)
{
    Suite *suite = suite_create("header");

    TCase *tc_header = tcase_create("core");
    tcase_add_test(tc_header, test_cjose_header_new_release);
    tcase_add_test(tc_header, test_cjose_header_retain_release);
    tcase_add_test(tc_header, test_cjose_header_set_get);
    tcase_add_test(tc_header, test_cjose_header_set_get_raw);
    tcase_add_test(tc_header, test_cjose_header_validate_crit);
    suite_add_tcase(suite, tc_header);

    return suite;
}
