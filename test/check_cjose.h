/*!
 *
 */

#include <stdint.h>
#include <string.h>

#include <check.h>

#ifdef _WIN32
#define random rand
#endif

Suite *cjose_version_suite();
Suite *cjose_util_suite();
Suite *cjose_base64_suite();
Suite *cjose_jwk_suite();
Suite *cjose_jwe_suite();
Suite *cjose_jws_suite();
Suite *cjose_header_suite();
Suite *cjose_utils_suite();
Suite *cjose_concatkdf_suite();

#define _ck_assert_bin(X, OP, Y, LEN)                                                                                            \
    do                                                                                                                           \
    {                                                                                                                            \
        const void *_chk_x = (X);                                                                                                \
        const void *_chk_y = (Y);                                                                                                \
        const size_t _chk_len = (LEN);                                                                                           \
        ck_assert_msg(0 OP memcmp(_chk_x, _chk_y, _chk_len),                                                                     \
                      "Assertion '" #X #OP #Y "' failed: " #LEN "==%zu, " #X "==%p, " #Y "==%p",                                 \
                      _chk_len, _chk_x, _chk_y);                                                                                 \
    } while (0);

#define ck_assert_bin_eq(X, Y, LEN) _ck_assert_bin(X, ==, Y, LEN)
