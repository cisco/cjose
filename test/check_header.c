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

static cjose_header_t *create_json(cjose_err *err)
{
    cjose_header_t *result = cjose_header_new(err);
    if (NULL == result)
    {
        return NULL;
    }

    if (    !cjose_header_set(result, "kty", "EC", err) ||
            !cjose_header_set(result, "crv", "P-256", err) ||
            !cjose_header_set(result, "kid", "MEbETzyljhGQor7vkwskW1Hm2iQvfLTIK_0CJhKF5a4", err) ||
            !cjose_header_set(result, "x", "np8fFwe9XXzCEyI5M1PHu0w2Tm387PN1M_1I0bg0cnI", err) ||
            !cjose_header_set(result, "y", "KAlnq-yxfrsRakc-inGOIiZtNyQrS_b2QWxtWChA5G0", err))
    {
        cjose_header_release(result);
        return NULL;
    }

    return result;
}

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
    ck_assert_msg(result, "cjose_header_set failed to get ALG");

    enc_get = cjose_header_get(header, CJOSE_HDR_ENC, &err);
    ck_assert_msg(result, "cjose_header_set failed to get ENC");

    ck_assert_msg(!strcmp(alg_set, alg_get), "cjose_header_get failed, "
                                             "expected: %s, found: %s",
                  ((alg_set) ? alg_set : "null"), ((alg_get) ? alg_get : "null"));

    ck_assert_msg(!strcmp(enc_set, enc_get), "cjose_header_get failed, "
                                             "expected: %s, found: %s",
                  ((enc_set) ? enc_set : "null"), ((enc_get) ? enc_get : "null"));

    cjose_header_release(header);
}
END_TEST

START_TEST(test_cjose_header_set_get_object)
{
    cjose_err err;
    bool result;

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");

    cjose_header_t *epk_set = create_json(&err);
    ck_assert_msg(NULL != epk_set, "create_json failed");

    result = cjose_header_set_object(header, CJOSE_HDR_EPK, epk_set, &err);
    ck_assert_msg(result, "cjose_header_set_object failed to set EPK");

    cjose_header_t *epk_cpy = cjose_header_new(&err);
    ck_assert_msg(NULL != epk_cpy, "cjose_header_new epk_cpy failed");

    json_object_update((json_t *)epk_cpy, (json_t *)epk_set);
    cjose_header_t *epk_get = cjose_header_get_object(header, CJOSE_HDR_EPK, &err);
    ck_assert_msg(epk_get, "cjose_header_get_object failed to get EPK");
    result = json_equal((json_t *)epk_get, (json_t *)epk_cpy);
    ck_assert_msg(result, "json_equal failed");

    cjose_header_release(header);
    cjose_header_release(epk_set);
    cjose_header_release(epk_cpy);
}
END_TEST

Suite *cjose_header_suite()
{
    Suite *suite = suite_create("header");

    TCase *tc_header = tcase_create("core");
    tcase_add_test(tc_header, test_cjose_header_new_release);
    tcase_add_test(tc_header, test_cjose_header_retain_release);
    tcase_add_test(tc_header, test_cjose_header_set_get);
    tcase_add_test(tc_header, test_cjose_header_set_get_object);
    suite_add_tcase(suite, tc_header);

    return suite;
}
