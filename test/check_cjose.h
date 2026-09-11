/*!
 *
 */

#include <stdint.h>
#include <string.h>

#include <check.h>

// Check 0.9.4 and 0.9.5 predate the ck_assert family, which 0.9.6 added on
// top of fail_unless, and ck_assert_uint_eq only arrived in 0.9.10; these
// are the definitions of the release that introduced each, with the integer
// comparisons printing intmax_t and uintmax_t like later releases do
#ifndef ck_assert_msg
#define ck_assert_msg fail_unless
#endif
#ifndef ck_assert
#define ck_assert(C) ck_assert_msg(C, NULL)
#endif
#ifndef ck_assert_int_eq
#define ck_assert_int_eq(X, Y) \
    ck_assert_msg((X) == (Y), "Assertion '" #X "==" #Y "' failed: " #X "==%jd, " #Y "==%jd", (intmax_t)(X), (intmax_t)(Y))
#endif
#ifndef ck_assert_uint_eq
#define ck_assert_uint_eq(X, Y) \
    ck_assert_msg((X) == (Y), "Assertion '" #X "==" #Y "' failed: " #X "==%ju, " #Y "==%ju", (uintmax_t)(X), (uintmax_t)(Y))
#endif
#ifndef ck_assert_str_eq
#define ck_assert_str_eq(X, Y) \
    ck_assert_msg(0 == strcmp(X, Y), "Assertion '" #X "==" #Y "' failed: " #X "==\"%s\", " #Y "==\"%s\"", X, Y)
#endif

#ifdef _WIN32
#define random rand
#endif

Suite *cjose_version_suite(void);
Suite *cjose_util_suite(void);
Suite *cjose_base64_suite(void);
Suite *cjose_jwk_suite(void);
Suite *cjose_jwe_suite(void);
Suite *cjose_jws_suite(void);
Suite *cjose_header_suite(void);
Suite *cjose_utils_suite(void);
Suite *cjose_concatkdf_suite(void);

#define _ck_assert_bin(X, OP, Y, LEN)                                                                                       \
    do                                                                                                                      \
    {                                                                                                                       \
        const void *_chk_x = (X);                                                                                           \
        const void *_chk_y = (Y);                                                                                           \
        const size_t _chk_len = (LEN);                                                                                      \
        ck_assert_msg(0 OP memcmp(_chk_x, _chk_y, _chk_len),                                                                \
                      "Assertion '" #X #OP #Y "' failed: " #LEN "==%zu, " #X "==%p, " #Y "==%p", _chk_len, _chk_x, _chk_y); \
    } while (0);

#define ck_assert_bin_eq(X, Y, LEN) _ck_assert_bin(X, ==, Y, LEN)
