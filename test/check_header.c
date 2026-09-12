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
#include "include/header_int.h"

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

    ck_assert_msg(!strcmp(alg_set, alg_get),
                  "cjose_header_get failed, "
                  "expected: %s, found: %s",
                  ((alg_set) ? alg_set : "null"), ((alg_get) ? alg_get : "null"));

    ck_assert_msg(!strcmp(enc_set, enc_get),
                  "cjose_header_get failed, "
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

    ck_assert_msg(!strcmp(epk_set, epk_get),
                  "cjose_header_get_raw failed, "
                  "expected: %s, found %s",
                  ((epk_set) ? epk_set : "null"), ((epk_get) ? epk_get : "null"));

    // cjose_header_get_raw returns a json_dumps() result owned by the caller
    cjose_get_dealloc()(epk_get);

    // a top-level scalar JSON value (e.g. RFC 7797 "b64":false) must round-trip;
    // jansson's default decode mode rejects these, JSON_DECODE_ANY accepts them
    result = cjose_header_set_raw(header, "b64", "false", &err);
    ck_assert_msg(result, "cjose_header_set_raw failed to set a scalar (boolean) value");

    char *b64_get = cjose_header_get_raw(header, "b64", &err);
    ck_assert_msg(NULL != b64_get && !strcmp(b64_get, "false"),
                  "cjose_header_get_raw failed to round-trip a scalar value, found %s", ((b64_get) ? b64_get : "null"));
    cjose_get_dealloc()(b64_get);
    cjose_header_release(header);
}
END_TEST

// RFC 7515 section 4.1.11: the "crit" list, if present, must be a non-empty
// array of supported, non-duplicate names that occur in the JOSE header, and it
// must be integrity protected, so it may only appear in the protected header
START_TEST(test_cjose_header_validate_crit)
{
    cjose_err err;
    static const char *const supported[] = { "alg", "cty" };
    const size_t supported_len = sizeof(supported) / sizeof(supported[0]);

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");
    cjose_header_t *headers[] = { header, NULL };
    const size_t headers_len = sizeof(headers) / sizeof(headers[0]);

    // no "crit" header at all is fine
    ck_assert(_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));

    // a supported extension that occurs in the header is fine
    ck_assert(cjose_header_set(header, "cty", "JWT", &err));
    ck_assert(cjose_header_set_raw(header, "crit", "[\"cty\"]", &err));
    ck_assert(_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));

    // an unsupported extension is rejected
    ck_assert(cjose_header_set_raw(header, "crit", "[\"exp\"]", &err));
    ck_assert(!_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // a non-array value is rejected
    ck_assert(cjose_header_set(header, "crit", "cty", &err));
    ck_assert(!_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // an empty list is rejected (RFC 7515 section 4.1.11)
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set_raw(header, "crit", "[]", &err));
    ck_assert(!_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // a duplicate name is rejected
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set_raw(header, "crit", "[\"cty\",\"cty\"]", &err));
    ck_assert(!_cjose_header_validate_crit(headers, headers_len, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // the list is refused in a header other than the protected one
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set_raw(header, "crit", "[\"cty\"]", &err));
    cjose_header_t *other = cjose_header_new(&err);
    ck_assert(NULL != other);
    ck_assert(cjose_header_set_raw(other, "crit", "[\"cty\"]", &err));
    cjose_header_t *both[] = { header, other };
    ck_assert(!_cjose_header_validate_crit(both, 2, supported, supported_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    cjose_header_release(other);
    cjose_header_release(header);
}
END_TEST

// RFC 7515 section 4.1.11: a name in the "crit" list must occur as a header
// parameter name within the JOSE header
START_TEST(test_cjose_header_validate_crit_present)
{
    cjose_err err;

    cjose_header_t *header = cjose_header_new(&err);
    ck_assert_msg(NULL != header, "cjose_header_new failed");
    cjose_header_t *headers[] = { header, NULL };
    const size_t headers_len = sizeof(headers) / sizeof(headers[0]);

    // no "crit" header at all is fine
    ck_assert(_cjose_header_validate_crit_present(headers, headers_len, &err));

    // a name that does not occur in the JOSE header is rejected
    ck_assert(cjose_header_set_raw(header, "crit", "[\"cty\"]", &err));
    ck_assert(!_cjose_header_validate_crit_present(headers, headers_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // ... and accepted once it does
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set(header, "cty", "JWT", &err));
    ck_assert(_cjose_header_validate_crit_present(headers, headers_len, &err));

    // the name may occur in any of the headers that make up the JOSE header
    cjose_header_t *other = cjose_header_new(&err);
    ck_assert(NULL != other);
    ck_assert(cjose_header_set(other, "alg", "HS256", &err));
    ck_assert(cjose_header_set_raw(header, "crit", "[\"alg\"]", &err));
    ck_assert(!_cjose_header_validate_crit_present(headers, headers_len, &err));
    cjose_header_t *both[] = { header, other };
    memset(&err, 0, sizeof(err));
    ck_assert(_cjose_header_validate_crit_present(both, 2, &err));

    cjose_header_release(other);
    cjose_header_release(header);
}
END_TEST

// RFC 7516 section 7.2.1: the member names of the JWE protected header, the
// shared unprotected header and a per-recipient unprotected header are disjoint
START_TEST(test_cjose_header_validate_disjoint)
{
    cjose_err err;

    cjose_header_t *protected_header = cjose_header_new(&err);
    cjose_header_t *shared = cjose_header_new(&err);
    cjose_header_t *personal = cjose_header_new(&err);
    ck_assert(NULL != protected_header && NULL != shared && NULL != personal);
    ck_assert(cjose_header_set(protected_header, "enc", "A128GCM", &err));
    ck_assert(cjose_header_set(shared, "cty", "JWT", &err));
    ck_assert(cjose_header_set(personal, "alg", "A128KW", &err));

    cjose_header_t *headers[] = { protected_header, shared, personal };
    const size_t headers_len = sizeof(headers) / sizeof(headers[0]);
    ck_assert(_cjose_header_validate_disjoint(headers, headers_len, &err));

    // a NULL entry is skipped
    cjose_header_t *with_null[] = { protected_header, NULL, personal };
    ck_assert(_cjose_header_validate_disjoint(with_null, headers_len, &err));

    // the same name in the protected and the per-recipient header is refused
    ck_assert(cjose_header_set(personal, "enc", "A128GCM", &err));
    ck_assert(!_cjose_header_validate_disjoint(headers, headers_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    // ... as is the same name in the shared and the per-recipient header
    memset(&err, 0, sizeof(err));
    ck_assert(cjose_header_set_raw(personal, "enc", "null", &err));
    json_object_del((json_t *)personal, "enc");
    ck_assert(_cjose_header_validate_disjoint(headers, headers_len, &err));
    ck_assert(cjose_header_set(personal, "cty", "JWT", &err));
    ck_assert(!_cjose_header_validate_disjoint(headers, headers_len, &err));
    ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);

    cjose_header_release(personal);
    cjose_header_release(shared);
    cjose_header_release(protected_header);
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
    tcase_add_test(tc_header, test_cjose_header_validate_crit_present);
    tcase_add_test(tc_header, test_cjose_header_validate_disjoint);
    suite_add_tcase(suite, tc_header);

    return suite;
}
