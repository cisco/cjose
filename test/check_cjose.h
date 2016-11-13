/*!
 *
 */

// the check unit test framework headers are noisy, disable these warnings
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"
#pragma GCC diagnostic ignored "-Wpointer-sign"

#include <check.h>

Suite *cjose_version_suite();
Suite *cjose_util_suite();
Suite *cjose_base64_suite();
Suite *cjose_jwk_suite();
Suite *cjose_jwe_suite();
Suite *cjose_jws_suite();
Suite *cjose_header_suite();
Suite *cjose_utils_suite();

#define _ck_assert_bin(X, OP, Y, LEN)                                                                                            \
    do                                                                                                                           \
    {                                                                                                                            \
        const uint8_t *_chk_x = (X);                                                                                             \
        const uint8_t *_chk_y = (Y);                                                                                             \
        const size_t _chk_len = (LEN);                                                                                           \
        ck_assert_msg(0 OP memcmp(_chk_x, _chk_y, _chk_len), "Assertion '" #X #OP #Y "' failed: " #X "==0x%zx, 0x" #Y "==0x%zx", \
                      _chk_x, _chk_y);                                                                                           \
    } while (0);

#define ck_assert_bin_eq(X, Y, LEN) _ck_assert_bin(X, ==, Y, LEN)
