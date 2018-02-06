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
    const char *epk_get, *epk_set = "{\"kty\":\"EC\","
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

    cjose_header_release(header);
}
END_TEST

Suite *cjose_header_suite()
{
    Suite *suite = suite_create("header");

    TCase *tc_header = tcase_create("core");
    tcase_add_test(tc_header, test_cjose_header_new_release);
    tcase_add_test(tc_header, test_cjose_header_retain_release);
    tcase_add_test(tc_header, test_cjose_header_set_get);
    tcase_add_test(tc_header, test_cjose_header_set_get_raw);
    suite_add_tcase(suite, tc_header);

    return suite;
}
