#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <string.h>

typedef struct {
    int tests_run;
    int passed;
    int failed;
} TestStats;

/*
 * Testing matters because IDS code changes often touch parsing, logging, and
 * detection at the same time. Small repeatable tests let beginners refactor
 * safely without needing live network traffic for every check.
 */
#define TEST_BEGIN(name_literal) const char *test_name = (name_literal)

#define ASSERT_TRUE(condition, message)                                      \
    do {                                                                     \
        if (!(condition)) {                                                   \
            printf("[FAIL] %s: %s\n", test_name, (message));                 \
            return 0;                                                         \
        }                                                                    \
    } while (0)

#define ASSERT_EQ_INT(expected, actual, message)                              \
    ASSERT_TRUE((expected) == (actual), (message))

#define ASSERT_STR_EQ(expected, actual, message)                              \
    ASSERT_TRUE(strcmp((expected), (actual)) == 0, (message))

#define TEST_PASS()                                                          \
    do {                                                                     \
        printf("[PASS] %s\n", test_name);                                    \
        return 1;                                                            \
    } while (0)

#define RUN_TEST(stats, test_function)                                       \
    do {                                                                     \
        (stats)->tests_run++;                                                \
        if ((test_function)()) {                                              \
            (stats)->passed++;                                               \
        } else {                                                             \
            (stats)->failed++;                                               \
        }                                                                    \
    } while (0)

#endif
