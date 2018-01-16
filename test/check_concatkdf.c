/*!
 *
 */

#include "check_cjose.h"

#include "include/concatkdf_int.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <cjose/base64.h>
#include <cjose/error.h>
#include <cjose/header.h>
#include <cjose/util.h>

#include <stdio.h>

static cjose_header_t *_create_otherinfo_header(const uint8_t *apu, const size_t apuLen, const uint8_t *apv, const size_t apvLen, cjose_err *err)
{
    cjose_header_t *result = NULL;
    cjose_header_t *hdr = NULL;
    char *apuB64 = NULL;
    size_t apuB64len = 0;
    char *apvB64 = NULL;
    size_t apvB64len = 0;

    memset(err, 0, sizeof(cjose_err));
    if (NULL != apu && !cjose_base64url_encode(apu, apuLen, &apuB64, &apuB64len, err))
    {
        goto _create_otherinfo_header_finish;
    }
    if (NULL != apv && !cjose_base64url_encode(apv, apvLen, &apvB64, &apvB64len, err))
    {
        goto _create_otherinfo_header_finish;
    }

    hdr = cjose_header_new(err);
    if (NULL == hdr)
    {
        goto _create_otherinfo_header_finish;
    }
    if (!(NULL == apuB64 || cjose_header_set(hdr, CJOSE_HDR_APU, apuB64, err)) ||
        !(NULL == apvB64 || cjose_header_set(hdr, CJOSE_HDR_APV, apvB64, err)))
    {
        goto _create_otherinfo_header_finish;
    }
    result = hdr;
    hdr = NULL;

_create_otherinfo_header_finish:
    cjose_get_dealloc()(apuB64);
    cjose_get_dealloc()(apvB64);
    cjose_header_release(hdr);
    ck_assert(err->code == CJOSE_ERR_NONE);

    return result;
}

static bool _cmp_uint32(uint8_t **actual, uint32_t expected)
{
    uint32_t value = htonl(expected);
    uint8_t expectedData[] = {
        (value >> 0) & 0xff,
        (value >> 8) & 0xff,
        (value >> 16) & 0xff,
        (value >> 24) & 0xff
    };
    bool result = (0 == memcmp(*actual, expectedData, 4));
    (*actual) += 4;
    return result;
}
static bool _cmp_lendata(uint8_t **actual, uint8_t *expected, size_t len)
{
    bool result = _cmp_uint32(actual, len);
    if (result && NULL != expected)
    {
        result = (0 == memcmp(*actual, expected, len));
    }
    (*actual) += len;
    return result;
}

START_TEST(test_cjose_concatkdf_otherinfo_noextra)
{
    cjose_err err;

    cjose_header_t *hdr = cjose_header_new(&err);
    uint8_t *otherinfo = NULL;
    size_t otherinfoLen = 0;
    uint8_t *actual = NULL;

    char *alg = "A256GCM";
    memset(&err, 0, sizeof(cjose_err));
    ck_assert(cjose_concatkdf_create_otherinfo(alg, 256, hdr, &otherinfo, &otherinfoLen, &err));
    actual = otherinfo;
    ck_assert_uint_eq(otherinfoLen, 23);
    ck_assert(_cmp_lendata(&actual, alg, strlen(alg))); // ALG
    ck_assert(_cmp_lendata(&actual, NULL, 0));          // APU
    ck_assert(_cmp_lendata(&actual, NULL, 0));          // APV
    ck_assert(_cmp_uint32(&actual, 256));               // KEYLEN
}
END_TEST

START_TEST(test_cjose_concatkdf_otherinfo_apuapv)
{
    cjose_err err;

    const uint8_t *apu = "expected apu";
    const size_t apuLen = strlen((const char *)apu);
    const uint8_t *apv = "expected apv";
    const size_t apvLen = strlen((const char *)apv);
    cjose_header_t *hdr = _create_otherinfo_header(apu, apuLen, apv, apvLen, &err);
    uint8_t *otherinfo = NULL;
    size_t otherinfoLen = 0;
    uint8_t *actual = NULL;

    char *alg = "A256GCM";
    memset(&err, 0, sizeof(cjose_err));
    ck_assert(cjose_concatkdf_create_otherinfo(alg, 32, hdr, &otherinfo, &otherinfoLen, &err));
    actual = otherinfo;
    ck_assert_uint_eq(otherinfoLen, 47);
    ck_assert(_cmp_lendata(&actual, alg, strlen(alg)));
    ck_assert(_cmp_lendata(&actual, apu, apuLen));
    ck_assert(_cmp_lendata(&actual, apv, apvLen));
    ck_assert(_cmp_uint32(&actual, 32));
}
END_TEST

START_TEST(test_cjose_concatkdf_derive_simple)
{
    cjose_err err;
    uint8_t *otherinfo = NULL;
    size_t otherinfoLen = 0;
    uint8_t *derived = NULL;

    const size_t ikmLen = 32;
    uint8_t ikm[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const char *alg
        = "A256GCM";
    const size_t keylen = 32;
    cjose_concatkdf_create_otherinfo(alg, keylen, cjose_header_new(&err), &otherinfo, &otherinfoLen, &err);
    derived = cjose_concatkdf_derive(keylen, ikm, ikmLen, otherinfo, otherinfoLen, &err);
    ck_assert(NULL != derived);

    uint8_t expected[] = {
        0xef, 0x1e, 0xe5, 0x58, 0xb7, 0xa8, 0x60, 0x06,
        0xe1, 0x6b, 0x26, 0x92, 0x5d, 0x14, 0xcc, 0x1b,
        0xa3, 0xbb, 0x4e, 0xcf, 0x0d, 0xf0, 0xb0, 0x49,
        0xaa, 0xc0, 0x3c, 0xef, 0x87, 0x34, 0xbd, 0x20
    };
    ck_assert_bin_eq(derived, expected, keylen);
}
END_TEST

START_TEST(test_cjose_concatkdf_derive_ikm)
{
    cjose_err err;
    uint8_t *otherinfo = NULL;
    size_t otherinfoLen = 0;
    uint8_t *derived = NULL;

    const size_t ikmLen = 32;
    uint8_t ikm[] = {
        0x86, 0x6f, 0x6f, 0xbb, 0x00, 0xf1, 0x7e, 0x2a,
        0x35, 0x34, 0x03, 0x6c, 0x10, 0x24, 0xe1, 0x3c,
        0x5f, 0x9f, 0x3e, 0x32, 0xa0, 0x43, 0xfe, 0x90,
        0x3c, 0x4b, 0x94, 0xf1, 0x62, 0xcc, 0xcd, 0x20
    };

    const char *alg = "A256GCM";
    const size_t keylen = 32;
    cjose_concatkdf_create_otherinfo(alg, keylen, cjose_header_new(&err), &otherinfo, &otherinfoLen, &err);
    derived = cjose_concatkdf_derive(keylen, ikm, ikmLen, otherinfo, otherinfoLen, &err);
    ck_assert(NULL != derived);

    uint8_t expected[] = {
        0x34, 0x85, 0xb0, 0x65, 0x0a, 0xa0, 0x95, 0xcc,
        0xd1, 0xc4, 0xd2, 0x5f, 0x97, 0x23, 0x50, 0x63,
        0x53, 0x77, 0xef, 0x05, 0xaa, 0x22, 0x82, 0x3d,
        0x6a, 0x23, 0x12, 0x39, 0xd2, 0x33, 0x6e, 0x44
    };
    ck_assert_bin_eq(derived, expected, keylen);
}
END_TEST

START_TEST(test_cjose_concatkdf_derive_moreinfo)
{
    cjose_err err;
    uint8_t *otherinfo = NULL;
    size_t otherinfoLen = 0;
    uint8_t *derived = NULL;

    const size_t ikmLen = 32;
    uint8_t ikm[] = {
        0x86, 0x6f, 0x6f, 0xbb, 0x00, 0xf1, 0x7e, 0x2a,
        0x35, 0x34, 0x03, 0x6c, 0x10, 0x24, 0xe1, 0x3c,
        0x5f, 0x9f, 0x3e, 0x32, 0xa0, 0x43, 0xfe, 0x90,
        0x3c, 0x4b, 0x94, 0xf1, 0x62, 0xcc, 0xcd, 0x20
    };

    const char *alg = "A256GCM";
    const size_t keylen = 32;
    cjose_header_t *hdr = _create_otherinfo_header("expected apu", strlen("expected apu"),
                                                   "expected apv", strlen("expected apv"),
                                                   &err);
    cjose_concatkdf_create_otherinfo(alg, keylen, hdr, &otherinfo, &otherinfoLen, &err);
    derived = cjose_concatkdf_derive(keylen, ikm, ikmLen, otherinfo, otherinfoLen, &err);
    ck_assert(NULL != derived);

    uint8_t expected[] = {
        0x2f, 0xc0, 0x7b, 0x68, 0x8d, 0x15, 0x1e, 0x30,
        0x1e, 0xf7, 0xb8, 0x3b, 0xf3, 0x46, 0x7a, 0xf0,
        0x0e, 0x94, 0xac, 0xfc, 0x18, 0xb5, 0xb4, 0xae,
        0x53, 0x81, 0xe0, 0x4a, 0x57, 0x1b, 0x58, 0x65
    };
    ck_assert_bin_eq(derived, expected, keylen);
}
END_TEST
Suite *cjose_concatkdf_suite()
{
    Suite *suite = suite_create("concatkdf");

    TCase *tc_concatkdf = tcase_create("concatkdf");
    tcase_add_test(tc_concatkdf, test_cjose_concatkdf_otherinfo_noextra);
    tcase_add_test(tc_concatkdf, test_cjose_concatkdf_otherinfo_apuapv);
    tcase_add_test(tc_concatkdf, test_cjose_concatkdf_derive_simple);
    tcase_add_test(tc_concatkdf, test_cjose_concatkdf_derive_ikm);
    tcase_add_test(tc_concatkdf, test_cjose_concatkdf_derive_moreinfo);
    suite_add_tcase(suite, tc_concatkdf);

    return suite;
}
