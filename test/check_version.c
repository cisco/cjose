/*!
 *
 */

// the check unit test framework headers are noisy, disable these warnings
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#include <stdlib.h>
#include <check.h>
#include <cjose/version.h>

START_TEST(test_cjose_version_define) { ck_assert_str_eq(CJOSE_VERSION, VERSION); }
END_TEST

START_TEST(test_cjose_version_fn)
{
    const char *version = cjose_version();
    ck_assert_str_eq(version, VERSION);
}
END_TEST

Suite *cjose_version_suite(void)
{
    Suite *suite = suite_create("version");

    TCase *tc_core = tcase_create("version");
    tcase_add_test(tc_core, test_cjose_version_define);
    tcase_add_test(tc_core, test_cjose_version_fn);
    suite_add_tcase(suite, tc_core);

    return suite;
}
