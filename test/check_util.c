
#include "check_cjose.h"
#include <cjose/util.h>
#include <check.h>
#include <jansson.h>
#include <stdlib.h>

static void *test_alloc(size_t amt)
{
    // TODO: verify amount requested
    return malloc(amt);
}

static void *test_realloc(void *ptr, size_t amt)
{
    // TODO: verify pointer to change & amount requested
    return realloc(ptr, amt);
}

static void test_dealloc(void *ptr)
{
    // TODO: verify pointer requested
    free(ptr);
}

START_TEST(test_cjose_set_allocators)
{
    ck_assert(malloc == cjose_get_alloc());
    ck_assert(realloc == cjose_get_realloc());
    ck_assert(free == cjose_get_dealloc());

    cjose_set_alloc_funcs(test_alloc, test_realloc, test_dealloc);
    ck_assert(test_alloc == cjose_get_alloc());
    ck_assert(test_realloc == cjose_get_realloc());
    ck_assert(test_dealloc == cjose_get_dealloc());

    cjose_set_alloc_funcs(NULL, NULL, NULL);
    ck_assert(malloc == cjose_get_alloc());
    ck_assert(realloc == cjose_get_realloc());
    ck_assert(free == cjose_get_dealloc());


}
END_TEST

Suite *cjose_util_suite()
{
    Suite *suite = suite_create("util");

    TCase *tc_util = tcase_create("core");
    tcase_add_test(tc_util, test_cjose_set_allocators);
    suite_add_tcase(suite, tc_util);

    return suite;
}
