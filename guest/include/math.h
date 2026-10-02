#ifndef G_MATH_H
#define G_MATH_H
double trunc(double);
float truncf(float);
double floor(double);
float floorf(float);
double ceil(double);
float ceilf(float);
double fabs(double);
float fabsf(float);
double fmin(double, double);
double fmax(double, double);
float fminf(float, float);
float fmaxf(float, float);
double sqrt(double);
float sqrtf(float);
double copysign(double, double);
float copysignf(float, float);
double rint(double);
float rintf(float);
double nearbyint(double);
float nearbyintf(float);
double round(double);
float roundf(float);
long lrint(double);
long lrintf(float);
long long llrint(double);
long long llrintf(float);
int isnan(double);
int isinf(double);
double fmod(double, double);
float fmodf(float, float);
double nan(const char *);
float nanf(const char *);

#define INFINITY (__builtin_inf())
#define NAN      (__builtin_nan(""))
#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALF (__builtin_huge_valf())
#define M_PI 3.14159265358979323846
#define isnan(x)   __builtin_isnan(x)
#define isinf(x)   __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)
#define signbit(x) __builtin_signbit(x)
#define fpclassify(x) __builtin_fpclassify(0,1,4,3,2,x)
#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4
#endif
