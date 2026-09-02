
#include "check_cjose.h"

#include <stdlib.h>
#include <check.h>
#include <cjose/base64.h>
#include <cjose/util.h>

START_TEST(test_cjose_base64_encode)
{
    cjose_err err;
    char *output = NULL;
    size_t inlen = 0, outlen = 0;

    static const uint8_t hello[] = "hello there";
    inlen = sizeof(hello) - 1;
    ck_assert(cjose_base64_encode(hello, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("aGVsbG8gdGhlcmU=", output);
    cjose_get_dealloc()(output);

    static const uint8_t spaced[] = "A B C D E F ";
    inlen = sizeof(spaced) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(spaced, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("QSBCIEMgRCBFIEYg", output);
    cjose_get_dealloc()(output);

    static const uint8_t nonascii[] = "hello\xfethere";
    inlen = sizeof(nonascii) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(nonascii, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("aGVsbG/+dGhlcmU=", output);
    cjose_get_dealloc()(output);

    static const uint8_t fe[] = "\xfe";
    inlen = sizeof(fe) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(fe, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("/g==", output);
    cjose_get_dealloc()(output);

    static const uint8_t one_two[] = "\x01\x02";
    inlen = sizeof(one_two) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(one_two, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("AQI=", output);
    cjose_get_dealloc()(output);

    static const uint8_t one[] = "\x01";
    inlen = sizeof(one) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(one, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_str_eq("AQ==", output);
    cjose_get_dealloc()(output);

    static const uint8_t empty[] = "";
    inlen = sizeof(empty) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(empty, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // input may be NULL iff inlen is 0
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_encode(NULL, inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // invalid arguments -- output == NULL
    static const uint8_t valid[] = "valid";
    inlen = sizeof(valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_encode(valid, inlen, NULL, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_encode(valid, inlen, &output, NULL, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64url_encode)
{
    cjose_err err;
    char *output = NULL;
    size_t inlen = 0, outlen = 0;

    static const uint8_t hello[] = "hello there";
    inlen = sizeof(hello) - 1;
    ck_assert(cjose_base64url_encode(hello, inlen, &output, &outlen, &err));
    ck_assert_int_eq(15, outlen);
    ck_assert_str_eq("aGVsbG8gdGhlcmU", output);
    cjose_get_dealloc()(output);

    static const uint8_t spaced[] = "A B C D E F ";
    inlen = sizeof(spaced) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(spaced, inlen, &output, &outlen, &err));
    ck_assert_int_eq(16, outlen);
    ck_assert_str_eq("QSBCIEMgRCBFIEYg", output);
    cjose_get_dealloc()(output);

    static const uint8_t nonascii[] = "hello\xfethere";
    inlen = sizeof(nonascii) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(nonascii, inlen, &output, &outlen, &err));
    ck_assert_int_eq(15, outlen);
    ck_assert_str_eq("aGVsbG_-dGhlcmU", output);
    cjose_get_dealloc()(output);

    static const uint8_t fe[] = "\xfe";
    inlen = sizeof(fe) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(fe, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_str_eq("_g", output);
    cjose_get_dealloc()(output);

    static const uint8_t one_two[] = "\x01\x02";
    inlen = sizeof(one_two) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(one_two, inlen, &output, &outlen, &err));
    ck_assert_int_eq(3, outlen);
    ck_assert_str_eq("AQI", output);
    cjose_get_dealloc()(output);

    static const uint8_t one[] = "\x01";
    inlen = sizeof(one) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(one, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_str_eq("AQ", output);
    cjose_get_dealloc()(output);

    static const uint8_t empty[] = "";
    inlen = sizeof(empty) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(empty, inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_str_eq("", output);
    cjose_get_dealloc()(output);

    // input may be NULL off inlen is 0
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_encode(NULL, inlen, &output, &outlen, &err));
    ck_assert_str_eq("", output);
    ck_assert(0 == outlen);
    cjose_get_dealloc()(output);

    // invalid arguments -- output == NULL
    static const uint8_t valid[] = "valid";
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_encode(valid, inlen, NULL, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_encode(valid, inlen, &output, NULL, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64_decode)
{
    cjose_err err;
    uint8_t *output = NULL;
    size_t inlen = 0, outlen = 0;

    static const char hello[] = "aGVsbG8gdGhlcmU=";
    inlen = sizeof(hello) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(hello, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq("hello there", output, 11);
    cjose_get_dealloc()(output);

    static const char spaced[] = "QSBCIEMgRCBFIEYg";
    inlen = sizeof(spaced) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(spaced, inlen, &output, &outlen, &err));
    ck_assert_int_eq(12, outlen);
    ck_assert_bin_eq("A B C D E F ", output, 12);
    cjose_get_dealloc()(output);

    static const char nonascii[] = "aGVsbG/+dGhlcmU=";
    inlen = sizeof(nonascii) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(nonascii, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq("hello\xfethere", output, 11);
    cjose_get_dealloc()(output);

    static const char fe[] = "/g==";
    inlen = sizeof(fe) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(fe, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq("\xfe", output, 1);
    cjose_get_dealloc()(output);

    static const char one_two[] = "AQI=";
    inlen = sizeof(one_two) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(one_two, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_bin_eq("\x01\x02", output, 2);
    cjose_get_dealloc()(output);

    static const char one[] = "AQ==";
    inlen = sizeof(one) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode(one, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq("\x01", output, 1);
    cjose_get_dealloc()(output);

    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64_decode("", inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_bin_eq("", output, 0);
    cjose_get_dealloc()(output);

    // invalid arguments -- input == NULL
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(NULL, inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- (inlen mod 4) != 0
    inlen = 5;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode("valids", inlen, &output, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- output == NULL
    static const char padded_valid[] = "valids==";
    inlen = sizeof(padded_valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(padded_valid, inlen, NULL, &outlen, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    inlen = sizeof(padded_valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64_decode(padded_valid, inlen, &output, NULL, &err));
    ck_assert(0 == outlen);
    ck_assert(NULL == output);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

START_TEST(test_cjose_base64url_decode)
{
    cjose_err err;
    uint8_t *output = NULL;
    size_t inlen = 0, outlen = 0;

    static const char hello[] = "aGVsbG8gdGhlcmU";
    inlen = sizeof(hello) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(hello, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq("hello there", output, 11);
    cjose_get_dealloc()(output);

    static const char spaced[] = "QSBCIEMgRCBFIEYg";
    inlen = sizeof(spaced) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(spaced, inlen, &output, &outlen, &err));
    ck_assert_int_eq(12, outlen);
    ck_assert_bin_eq("A B C D E F ", output, 12);
    cjose_get_dealloc()(output);

    static const char nonascii[] = "aGVsbG_-dGhlcmU";
    inlen = sizeof(nonascii) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(nonascii, inlen, &output, &outlen, &err));
    ck_assert_int_eq(11, outlen);
    ck_assert_bin_eq("hello\xfethere", output, 11);
    cjose_get_dealloc()(output);

    static const char fe[] = "_g";
    inlen = sizeof(fe) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(fe, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq("\xfe", output, 1);
    cjose_get_dealloc()(output);

    static const char one_two[] = "AQI";
    inlen = sizeof(one_two) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(one_two, inlen, &output, &outlen, &err));
    ck_assert_int_eq(2, outlen);
    ck_assert_bin_eq("\x01\x02", output, 2);
    cjose_get_dealloc()(output);

    static const char one[] = "AQ";
    inlen = sizeof(one) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(one, inlen, &output, &outlen, &err));
    ck_assert_int_eq(1, outlen);
    ck_assert_bin_eq("\x01", output, 1);
    cjose_get_dealloc()(output);

    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode("", inlen, &output, &outlen, &err));
    ck_assert_int_eq(0, outlen);
    ck_assert_bin_eq("", output, 0);
    cjose_get_dealloc()(output);

    static const char valid[] = "valids";
    inlen = sizeof(valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(cjose_base64url_decode(valid, inlen, &output, &outlen, &err));
    ck_assert_int_eq(4, outlen);
    ck_assert_bin_eq("\xbd\xa9\x62\x76", output, 4);
    cjose_get_dealloc()(output);

    // invalid arguments -- input == NULL
    inlen = 0;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(NULL, inlen, &output, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- output == NULL
    inlen = sizeof(valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(valid, inlen, NULL, &outlen, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);

    // invalid arguments -- outlen == NULL
    inlen = sizeof(valid) - 1;
    output = NULL;
    outlen = 0;
    ck_assert(!cjose_base64url_decode(valid, inlen, &output, NULL, &err));
    ck_assert(NULL == output);
    ck_assert(0 == outlen);
    ck_assert(err.code == CJOSE_ERR_INVALID_ARG);
}
END_TEST

Suite *cjose_base64_suite(void)
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
