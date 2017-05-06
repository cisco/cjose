
#include "check_cjose.h"
#include <cjose/util.h>
#include <check.h>
#include <jansson.h>
#include <stdlib.h>
#include "include/util_int.h"

static size_t _test_alloc_in_amt;
static void *_test_alloc_in_ptr;
static void *_test_alloc_out_ptr;
static void *test_alloc(size_t amt)
{
    _test_alloc_in_amt = amt;
    _test_alloc_out_ptr = malloc(amt);
    return _test_alloc_out_ptr;
}

static void *test_realloc(void *ptr, size_t amt)
{
    _test_alloc_in_ptr = ptr;
    _test_alloc_in_amt = amt;
    _test_alloc_out_ptr = realloc(ptr, amt);
    return _test_alloc_out_ptr;
}

static void test_dealloc(void *ptr)
{
    _test_alloc_in_ptr = ptr;
    free(ptr);
}

static void test_alloc_reset()
{
    _test_alloc_in_amt = 0;
    _test_alloc_in_ptr = _test_alloc_out_ptr = NULL;
}

START_TEST(test_cjose_set_allocators)
{
    // Simply verify return ptr is not NULL
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());

    // Simply verify return ptr is not NULL
    cjose_set_alloc_funcs(test_alloc, test_realloc, test_dealloc);
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());

    // test simple allocation/reallocation/deallocation redirect
    size_t amt;
    void *ptr;
    void *re_ptr;

    test_alloc_reset();

    amt = 129;
    ptr = cjose_get_alloc()(amt);
    ck_assert(amt == _test_alloc_in_amt);
    ck_assert(ptr == _test_alloc_out_ptr);

    amt = 319;
    re_ptr = cjose_get_realloc()(ptr, amt);
    ck_assert(amt == _test_alloc_in_amt);
    ck_assert(ptr == _test_alloc_in_ptr);
    ck_assert(re_ptr == _test_alloc_out_ptr);

    ptr = re_ptr;
    cjose_get_dealloc()(ptr);
    ck_assert(ptr == _test_alloc_out_ptr);

    // test extended allocation/reallocation/deallocation redirect
    test_alloc_reset();

    amt = 129;
    ptr = cjose_get_alloc3()(amt, __FILE__, __LINE__);
    ck_assert(amt == _test_alloc_in_amt);
    ck_assert(ptr == _test_alloc_out_ptr);

    amt = 319;
    re_ptr = cjose_get_realloc3()(ptr, amt, __FILE__, __LINE__);
    ck_assert(amt == _test_alloc_in_amt);
    ck_assert(ptr == _test_alloc_in_ptr);
    ck_assert(re_ptr == _test_alloc_out_ptr);

    ptr = re_ptr;
    cjose_get_dealloc3()(ptr, __FILE__, __LINE__);
    ck_assert(ptr == _test_alloc_out_ptr);

    // Simply verify return ptr is not NULL
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());
}
END_TEST

static size_t _test_alloc3_in_amt;
static void *_test_alloc3_in_ptr;
static const char *_test_alloc3_in_file;
static int _test_alloc3_in_line;
static void *_test_alloc3_out_ptr;
static void test_alloc3_reset()
{
    test_alloc_reset();
    _test_alloc3_in_amt = 0;
    _test_alloc3_in_ptr = _test_alloc3_out_ptr = NULL;
    _test_alloc3_in_file = NULL;
    _test_alloc3_in_line = 0;
}

static void *test_alloc3(size_t amt, const char *file, int line)
{
    _test_alloc3_in_amt = amt;
    _test_alloc3_in_file = file;
    _test_alloc3_in_line = line;
    _test_alloc3_out_ptr = malloc(amt);
    return _test_alloc3_out_ptr;
}

static void *test_realloc3(void *ptr, size_t amt, const char *file, int line)
{
    _test_alloc3_in_ptr = ptr;
    _test_alloc3_in_amt = amt;
    _test_alloc3_in_file = file;
    _test_alloc3_in_line = line;
    _test_alloc3_out_ptr = realloc(ptr, amt);
    return _test_alloc3_out_ptr;
}

static void test_dealloc3(void *ptr, const char *file, int line)
{
    _test_alloc3_in_ptr = ptr;
    _test_alloc3_in_file = file;
    _test_alloc3_in_line = line;
    free(ptr);
}

START_TEST(test_cjose_set_allocators_ex)
{
    // Simply verify return ptr is not NULL
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());

    cjose_set_alloc_ex_funcs(test_alloc3, test_realloc3, test_dealloc3);
    // Simply verify return ptr is not NULL
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());

    size_t amt;
    void *ptr;
    void *re_ptr;
    const char *file;
    int line;

    // test extended allocation/reallocation/deallocation redirect
    test_alloc3_reset();

    amt = 129;
    file = __FILE__;
    line = __LINE__;
    ptr = cjose_get_alloc3()(amt, file, line);
    ck_assert(amt == _test_alloc3_in_amt);
    ck_assert(ptr == _test_alloc3_out_ptr);
    ck_assert(file == _test_alloc3_in_file);
    ck_assert(line == _test_alloc3_in_line);

    amt = 319;
    file = __FILE__;
    line = __LINE__;
    re_ptr = cjose_get_realloc3()(ptr, amt, file, line);
    ck_assert(amt == _test_alloc3_in_amt);
    ck_assert(ptr == _test_alloc3_in_ptr);
    ck_assert(re_ptr == _test_alloc3_out_ptr);
    ck_assert(file == _test_alloc3_in_file);
    ck_assert(line == _test_alloc3_in_line);

    ptr = re_ptr;
    file = __FILE__;
    line = __LINE__;
    cjose_get_dealloc3()(ptr, file, line);
    ck_assert(ptr == _test_alloc3_in_ptr);
    ck_assert(file == _test_alloc3_in_file);
    ck_assert(line == _test_alloc3_in_line);

    // test simple allocation/reallocation/deallocation redirect
    test_alloc3_reset();

    amt = 129;
    ptr = cjose_get_alloc()(amt);
    ck_assert(amt == _test_alloc3_in_amt);
    ck_assert(ptr == _test_alloc3_out_ptr);
    ck_assert(NULL != _test_alloc3_in_file);
    ck_assert(0 != _test_alloc3_in_line);

    amt = 319;
    re_ptr = cjose_get_realloc()(ptr, amt);
    ck_assert(amt == _test_alloc3_in_amt);
    ck_assert(ptr == _test_alloc3_in_ptr);
    ck_assert(re_ptr == _test_alloc3_out_ptr);
    ck_assert(NULL != _test_alloc3_in_file);
    ck_assert(0 != _test_alloc3_in_line);

    ptr = re_ptr;
    cjose_get_dealloc()(ptr);
    ck_assert(ptr == _test_alloc3_in_ptr);
    ck_assert(NULL != _test_alloc3_in_file);
    ck_assert(0 != _test_alloc3_in_line);

    test_alloc3_reset();

    cjose_set_alloc_ex_funcs(NULL, NULL, NULL);
    // Simply verify return ptr is not NULL
    ck_assert(NULL != cjose_get_alloc());
    ck_assert(NULL != cjose_get_realloc());
    ck_assert(NULL != cjose_get_dealloc());
    ck_assert(NULL != cjose_get_alloc3());
    ck_assert(NULL != cjose_get_realloc3());
    ck_assert(NULL != cjose_get_dealloc3());
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
