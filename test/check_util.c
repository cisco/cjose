
#include "check_cjose.h"
#include <cjose/util.h>
#include <check.h>
#include <jansson.h>
#include <stdlib.h>
#include "include/util_int.h"

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
    ck_assert(cjose_alloc3_default == cjose_get_alloc3());
    ck_assert(cjose_realloc3_default == cjose_get_realloc3());
    ck_assert(cjose_dealloc3_default == cjose_get_dealloc3());

    cjose_set_alloc_funcs(test_alloc, test_realloc, test_dealloc);
    ck_assert(test_alloc == cjose_get_alloc());
    ck_assert(test_realloc == cjose_get_realloc());
    ck_assert(test_dealloc == cjose_get_dealloc());
    ck_assert(cjose_alloc3_default == cjose_get_alloc3());
    ck_assert(cjose_realloc3_default == cjose_get_realloc3());
    ck_assert(cjose_dealloc3_default == cjose_get_dealloc3());

    cjose_set_alloc_funcs(NULL, NULL, NULL);
    ck_assert(malloc == cjose_get_alloc());
    ck_assert(realloc == cjose_get_realloc());
    ck_assert(free == cjose_get_dealloc());
    ck_assert(cjose_alloc3_default == cjose_get_alloc3());
    ck_assert(cjose_realloc3_default == cjose_get_realloc3());
    ck_assert(cjose_dealloc3_default == cjose_get_dealloc3());
}
END_TEST

static void *test_alloc3(size_t amt, const char *file, int line)
{
    // TODO: verify amount requested
    return malloc(amt);
}

static void *test_realloc3(void *ptr, size_t amt, const char *file, int line)
{
    // TODO: verify pointer to change & amount requested
    return realloc(ptr, amt);
}

static void test_dealloc3(void *ptr, const char *file, int line)
{
    // TODO: verify pointer requested
    free(ptr);
}

START_TEST(test_cjose_set_allocators_ex)
{
    ck_assert(malloc == cjose_get_alloc());
    ck_assert(realloc == cjose_get_realloc());
    ck_assert(free == cjose_get_dealloc());
    ck_assert(cjose_alloc3_default == cjose_get_alloc3());
    ck_assert(cjose_realloc3_default == cjose_get_realloc3());
    ck_assert(cjose_dealloc3_default == cjose_get_dealloc3());

    cjose_set_alloc_ex_funcs(test_alloc3, test_realloc3, test_dealloc3);
    ck_assert(cjose_alloc_wrapped == cjose_get_alloc());
    ck_assert(cjose_realloc_wrapped == cjose_get_realloc());
    ck_assert(cjose_dealloc_wrapped == cjose_get_dealloc());
    ck_assert(test_alloc3 == cjose_get_alloc3());
    ck_assert(test_realloc3 == cjose_get_realloc3());
    ck_assert(test_dealloc3 == cjose_get_dealloc3());

    cjose_set_alloc_ex_funcs(NULL, NULL, NULL);
    ck_assert(malloc == cjose_get_alloc());
    ck_assert(realloc == cjose_get_realloc());
    ck_assert(free == cjose_get_dealloc());
    ck_assert(cjose_alloc3_default == cjose_get_alloc3());
    ck_assert(cjose_realloc3_default == cjose_get_realloc3());
    ck_assert(cjose_dealloc3_default == cjose_get_dealloc3());
}
END_TEST

Suite *cjose_util_suite()
{
    Suite *suite = suite_create("util");

    TCase *tc_util = tcase_create("core");
    tcase_add_test(tc_util, test_cjose_set_allocators);
    tcase_add_test(tc_util, test_cjose_set_allocators_ex);
    suite_add_tcase(suite, tc_util);

    return suite;
}
