/*!
 *
 */

#include "check_cjose.h"

#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>

Suite *cjose_suite(void)
{
    Suite *suite = suite_create("CJOSE");

    return suite;
}

int main(void)
{
    // initialize "OpenSSL" crypto
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // setup suites
    SRunner *runner = srunner_create(cjose_suite());

    srunner_set_fork_status(runner, CK_NOFORK);

    srunner_add_suite(runner, cjose_version_suite());
    srunner_add_suite(runner, cjose_util_suite());
    srunner_add_suite(runner, cjose_base64_suite());
    srunner_add_suite(runner, cjose_concatkdf_suite());
    srunner_add_suite(runner, cjose_jwk_suite());
    srunner_add_suite(runner, cjose_jwe_suite());
    srunner_add_suite(runner, cjose_jws_suite());
    srunner_add_suite(runner, cjose_header_suite());

    srunner_run_all(runner, CK_VERBOSE);
    int failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    // cleanup "OpenSSL" crypto
    EVP_cleanup();
    ERR_free_strings();

    return (0 == failed) ? EXIT_SUCCESS : EXIT_FAILURE;
}
