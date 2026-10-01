#ifndef MESG_H
#define MESG_H

#include <stdio.h>

#define MESG_LEVEL_DBUG 4
#define MESG_LEVEL_INFO 3
#define MESG_LEVEL_WARN 2
#define MESG_LEVEL_FAIL 1

#ifndef MESG_PLAIN
#define MESG_COLO_NORM "\x1B[0m"
#define MESG_PREF_DBUG \
    "\x1B[37m"         \
    "DBUG" MESG_COLO_NORM " "
#define MESG_PREF_INFO \
    "\x1B[34m"         \
    "INFO" MESG_COLO_NORM " "
#define MESG_PREF_WARN \
    "\x1B[33m"         \
    "WARN" MESG_COLO_NORM " "
#define MESG_PREF_FAIL \
    "\x1B[31m"         \
    "FAIL" MESG_COLO_NORM " "
#else
#define MESG_PREF_DBUG "DBUG "
#define MESG_PREF_INFO "INFO "
#define MESG_PREF_WARN "WARN "
#define MESG_PREF_FAIL "FAIL "
#endif

/* ##__VA_ARGS__ below lets MESG_*() be called with just a format string and
 * no extra args, which needs the GNU comma-paste extension in C99 (no
 * __VA_OPT__ until C23); both compilers this project builds with (gcc,
 * clang) support it identically. */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#define MESG_DBUG(FMT, ...)                                                  \
    do {                                                                     \
        if (mesg_get_level() >= MESG_LEVEL_DBUG) {                           \
            if (mesg_get_dbug_cb())                                          \
                mesg_get_dbug_cb()(mesg_get_data(), "%s+%u> " FMT, __FILE__, \
                                   __LINE__, ##__VA_ARGS__);                 \
            else                                                             \
                fprintf(stderr, MESG_PREF_DBUG "%s+%u> " FMT "\n", __FILE__, \
                        __LINE__, ##__VA_ARGS__);                            \
        }                                                                    \
    } while (0)

#define MESG_INFO(FMT, ...)                                                  \
    do {                                                                     \
        if (mesg_get_level() >= MESG_LEVEL_INFO) {                           \
            if (mesg_get_info_cb())                                          \
                mesg_get_info_cb()(mesg_get_data(), "%s+%u> " FMT, __FILE__, \
                                   __LINE__, ##__VA_ARGS__);                 \
            else                                                             \
                fprintf(stderr, MESG_PREF_INFO "%s+%u> " FMT "\n", __FILE__, \
                        __LINE__, ##__VA_ARGS__);                            \
        }                                                                    \
    } while (0)

#define MESG_WARN(FMT, ...)                                                  \
    do {                                                                     \
        if (mesg_get_level() >= MESG_LEVEL_WARN) {                           \
            if (mesg_get_warn_cb())                                          \
                mesg_get_warn_cb()(mesg_get_data(), "%s+%u> " FMT, __FILE__, \
                                   __LINE__, ##__VA_ARGS__);                 \
            else                                                             \
                fprintf(stderr, MESG_PREF_WARN "%s+%u> " FMT "\n", __FILE__, \
                        __LINE__, ##__VA_ARGS__);                            \
        }                                                                    \
    } while (0)

#define MESG_FAIL(FMT, ...)                                                  \
    do {                                                                     \
        if (mesg_get_level() >= MESG_LEVEL_FAIL) {                           \
            if (mesg_get_fail_cb())                                          \
                mesg_get_fail_cb()(mesg_get_data(), "%s+%u> " FMT, __FILE__, \
                                   __LINE__, ##__VA_ARGS__);                 \
            else                                                             \
                fprintf(stderr, MESG_PREF_FAIL "%s+%u> " FMT "\n", __FILE__, \
                        __LINE__, ##__VA_ARGS__);                            \
        }                                                                    \
    } while (0)

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*mesg_f)(const void* arg, const char* fmt, ...);

API_EXPORT int         mesg_get_level(void);
API_EXPORT void        mesg_set_level(const int);
API_EXPORT void        mesg_set_data(const void*);
API_EXPORT const void* mesg_get_data(void);
API_EXPORT void        mesg_set_dbug_cb(mesg_f);
API_EXPORT mesg_f      mesg_get_dbug_cb(void);
API_EXPORT void        mesg_set_info_cb(mesg_f);
API_EXPORT mesg_f      mesg_get_info_cb(void);
API_EXPORT void        mesg_set_warn_cb(mesg_f);
API_EXPORT mesg_f      mesg_get_warn_cb(void);
API_EXPORT void        mesg_set_fail_cb(mesg_f);
API_EXPORT mesg_f      mesg_get_fail_cb(void);

#ifdef __cplusplus
}
#endif

#endif /* MESG_H */
