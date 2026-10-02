#ifndef G_ASSERT_H
#define G_ASSERT_H
#ifdef NDEBUG
#define assert(x) ((void)0)
#else
void __assert_fail(const char *, const char *, unsigned, const char *);
#define assert(x) ((x) ? (void)0 : __assert_fail(#x, __FILE__, __LINE__, __func__))
#endif
#endif
