#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <time.h>

#ifndef TEST_PLAIN
#define TEST_COLOR_NORM    "\x1B[0m"
#define TEST_COLOR_BOLD(s) "\x1B[1m" s TEST_COLOR_NORM
#define TEST_COLOR_FAIL(s) "\x1B[31m" s TEST_COLOR_NORM
#define TEST_COLOR_PASS(s) "\x1B[32m" s TEST_COLOR_NORM
#define TEST_COLOR_SKIP(s) "\x1B[37m" s TEST_COLOR_NORM
#else
#define TEST_COLOR_BOLD(s) s
#define TEST_COLOR_FAIL(s) s
#define TEST_COLOR_PASS(s) s
#define TEST_COLOR_SKIP(s) s
#endif

char*   test_spec_name;
char*   location;
char*   error;
size_t  test_count;
size_t  test_count_fail;
size_t  test_count_skip;
clock_t test_start;
void    test_main();

static int test_status(const char* name, int count)
{
    double time = ((double)(clock() - test_start)) / CLOCKS_PER_SEC;
    ++test_count;
    printf("  ");
    if (!count) {
        ++test_count_skip;
        printf(TEST_COLOR_SKIP("SKIP") " %lfs/%-7d %s\n", 0.0, count, name);
    } else if (error == NULL) {
        printf(TEST_COLOR_PASS("PASS") " %lfs/%-7d %s\n", time, count, name);
    } else {
        ++test_count_fail;
        printf(TEST_COLOR_FAIL("FAIL") " %lfs/%-7d %s\n", time, count, name);
        printf("    %s %s\n", error, location);
        error = NULL;
    }
    return 0;
}

int main(void)
{
    printf(TEST_COLOR_BOLD("%s") "\n", test_spec_name);
    test_main();
    printf("\n%zu test%s, %zu failed\n", test_count, test_count == 1 ? "" : "s",
           test_count_fail);
    return !!test_count_fail;
}

#define TEST_NARGS_IMPL(_1, _2, N, ...) N
#define TEST_NARGS(...)                 TEST_NARGS_IMPL(__VA_ARGS__, 2, 1, 0)
#define TEST_CAT_IMPL(a, b)             a##b
#define TEST_CAT(a, b)                  TEST_CAT_IMPL(a, b)

#define spec(name)                 \
    char* test_spec_name = (name); \
    void  test_main()
#define context(name) printf("\n  " TEST_COLOR_BOLD(name) "\n");
#define it1(name, count)  \
    test_start = clock(); \
    for (int run = 1; run; run = test_status(name, count))
#define it2(name, count, ...) \
    it1 (name, count)         \
        for (int i = 0; i < count && !error; i++)
#define it(...) TEST_CAT(it, TEST_NARGS(__VA_ARGS__))(__VA_ARGS__, 1)
#define xit(name, ...)    \
    test_start = clock(); \
    for (; test_status(name, 0);)

#define TEST_STRING_IMPL(x) #x
#define TEST_STRING(x)      TEST_STRING_IMPL(x)
#define check(condition)                                     \
    if (!(condition)) {                                      \
        error    = "check(" TEST_COLOR_FAIL(#condition) ")"; \
        location = "at " __FILE__ ":" TEST_STRING(__LINE__); \
        continue;                                            \
    }

#endif /* TEST_H */
