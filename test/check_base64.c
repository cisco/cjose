
#include "check_cjose.h"

#include <stdlib.h>
#include <check.h>
#include <cjose/base64.h>
#include <cjose/util.h>

START_TEST(test_cjose_base64_encode)
{
    cjose_err err;
    uint8_t *input = NULL;
    char *output = NULL;
    size_t inlen = 0, outlen = 0;

    input = (uint8_t *)"hello there";
    inlen = 11;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("aGVsbG8gdGhlcmU=", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"A B C D E F ";
    inlen = 12;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("QSBCIEMgRCBFIEYg", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"hello\xfethere";
    inlen = 11;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("aGVsbG/+dGhlcmU=", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\xfe";
    inlen = 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("/g==", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\x01\x02";
    inlen = 2;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("AQI=", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\x01";
    inlen = 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("AQ==", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // input may be NULL iff inlen is 0
    input = NULL;
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(input, inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // invalid arguments -- output == NULL
    input = "valid";
    inlen = 5;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_encode(input, inlen, NULL, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    input = "valid";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_encode(input, inlen, &output, NULL, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64url_encode)
{
    cjose_err err;
    uint8_t *input = NULL;
    char *output = NULL;
    size_t inlen = 0, outlen = 0;

    input = (uint8_t *)"hello there";
    inlen = 11;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(15, outlen);
    ck_assert_str_eq("aGVsbG8gdGhlcmU", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"A B C D E F ";
    inlen = 12;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("QSBCIEMgRCBFIEYg", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"hello\xfethere";
    inlen = 11;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(15, outlen);
    ck_assert_str_eq("aGVsbG_-dGhlcmU", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\xfe";
    inlen = 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_str_eq("_g", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\x01\x02";
    inlen = 2;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(3, outlen);
    ck_assert_str_eq("AQI", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"\x01";
    inlen = 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_str_eq("AQ", output);
    cjose_get_dealloc()(output);

    input = (uint8_t *)"";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // input may be NULL off inlen is 0
    input = NULL;
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(input, inlen, &output, &outlen, &err));
    ck_assert_str_eq("", output);
    ck_assert(0 == outlen);
    cjose_get_dealloc()(output);

    // invalid arguments -- output == NULL
    input = "valid";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_encode(input, inlen, NULL, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    input = "valid";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_encode(input, inlen, &output, NULL, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64_decode)
{
    cjose_err err;
    char *input = NULL;
    uint8_t *output = NULL;
    size_t inlen = 0, outlen = 0;

    input = "aGVsbG8gdGhlcmU=";
    inlen = 16;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq((uint8_t *)"hello there", output, 11);
    cjose_get_dealloc()(output);

    input = "QSBCIEMgRCBFIEYg";
    inlen = 16;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(12, outlen);
    ck_assert_bin_eq((uint8_t *)"A B C D E F ", output, 12);
    cjose_get_dealloc()(output);

    input = "aGVsbG/+dGhlcmU=";
    inlen = 16;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq((uint8_t *)"hello\xfethere", output, 11);
    cjose_get_dealloc()(output);

    input = "/g==";
    inlen = 4;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq((uint8_t *)"\xfe", output, 1);
    cjose_get_dealloc()(output);

    input = "AQI=";
    inlen = 4;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_bin_eq((uint8_t *)"\x01\x02", output, 2);
    cjose_get_dealloc()(output);

    input = "AQ==";
    inlen = 4;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq((uint8_t *)"\x01", output, 1);
    cjose_get_dealloc()(output);

    input = "";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_bin_eq((uint8_t *)"", output, 0);
    cjose_get_dealloc()(output);

    // invalid arguments -- input == NULL
    input = NULL;
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- (inlen mod 4) != 0
    input = "valids";
    inlen = 5;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(input, inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- output == NULL
    input = "valids==";
    inlen = 8;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(input, inlen, NULL, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    input = "valids==";
    inlen = 8;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(input, inlen, &output, NULL, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64url_decode)
{
    cjose_err err;
    char *input = NULL;
    uint8_t *output = NULL;
    size_t inlen = 0, outlen = 0;

    input = "aGVsbG8gdGhlcmU";
    inlen = 15;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq((uint8_t *)"hello there", output, 11);
    cjose_get_dealloc()(output);

    input = "QSBCIEMgRCBFIEYg";
    inlen = 16;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(12, outlen);
    ck_assert_bin_eq((uint8_t *)"A B C D E F ", output, 12);
    cjose_get_dealloc()(output);

    input = "aGVsbG_-dGhlcmU";
    inlen = 15;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq((uint8_t *)"hello\xfethere", output, 11);
    cjose_get_dealloc()(output);

    input = "_g";
    inlen = 2;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq((uint8_t *)"\xfe", output, 1);
    cjose_get_dealloc()(output);

    input = "AQI";
    inlen = 3;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_bin_eq((uint8_t *)"\x01\x02", output, 2);
    cjose_get_dealloc()(output);

    input = "AQ";
    inlen = 2;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq((uint8_t *)"\x01", output, 1);
    cjose_get_dealloc()(output);

    input = "";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_bin_eq((uint8_t *)"", output, 0);
    cjose_get_dealloc()(output);

    input = "valids";
    inlen = 6;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_bin_eq((uint8_t *)"\xbd\xa9\x62\x76", output, 4);
    cjose_get_dealloc()(output);

    // invalid arguments -- input == NULL
    input = NULL;
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(input, inlen, &output, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- output == NULL
    input = "valids";
    inlen = 6;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(input, inlen, NULL, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    input = "valids";
    inlen = 6;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(input, inlen, &output, NULL, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

Suite *cjose_base64_suite()
{
    Suite *suite = suite_create("base64");

    TCase *tc_b64 = tcase_create("core");
    tcase_add_test(tc_b64, test_cjose_base64_encode);
    tcase_add_test(tc_b64, test_cjose_base64url_encode);
    tcase_add_test(tc_b64, test_cjose_base64_decode);
    tcase_add_test(tc_b64, test_cjose_base64url_decode);
    suite_add_tcase(suite, tc_b64);

    return suite;
}
