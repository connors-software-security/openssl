/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/newhope.h>

#include <openssl/e_os2.h>

#include <limits.h>

#if CHAR_BIT != 8
#error Must have CHAR_BIT == 8
#endif

/*
 * Define this to force treating poly_product_t as 32bit even if the platform
 * would actually support a 64-bit type for this.
 */
#undef FORCE_32BIT_POLY_PRODUCT_T

#if defined(NH_ASM)
/* All of the ASM NTT use 32 bit intermediate products */
#  define FORCE_32BIT_POLY_PRODUCT_T
#endif

/*
 * Define this to replace actual computations with code that just computes
 * the number of k-factors on each data item. Useful for checking that
 * everything is properly balanced.
 */
#undef CHECK_K

#ifdef FORCE_32BIT_POLY_PRODUCT_T
#define HAS_POLY_PRODUCT_T
typedef int poly_product_t;
#endif

/*
 * XXX I've just now noticed that files like modes_lcl.h seem to imply an
 * assumption that there is a 64-bit integer type available. Perhaps the
 * other platform tests are to not use a 64-bit type if it would make things
 * slower. In our case I expect that a fast multiply with 32-bit operands and
 * 64-bit result would be (nearly) universally available. So it might be worth
 * revisitng whether not having a 64-bit type is actually a case we need to
 * support, even if it negates the work I've done to get things working in
 * that situation.
 */
#if !defined(HAS_POLY_PRODUCT_T) && __STDC_VERSION__ >= 199901L
# include <stdint.h>
# if defined(INT_FAST64_MAX)
#  define POLY_PRODUCT_T_IS_64_BITS
#  define HAS_POLY_PRODUCT_T
typedef int_fast64_t poly_product_t;
# elif defined(INT_LEAST64_MAX)
#  define HAS_POLY_PRODUCT_T
#  define POLY_PRODUCT_T_IS_64_BITS
typedef int_least64_t poly_product_t;
# elif defined(INT64_MAX)
#  define HAS_POLY_PRODUCT_T
#  define POLY_PRODUCT_T_IS_64_BITS
typedef int64_t poly_product_t;
# endif
#endif

#if !defined(HAS_POLY_PRODUCT_T) && defined(_WIN32) && !defined(__GNUC__)
# define HAS_POLY_PRODUCT_T
# define POLY_PRODUCT_T_IS_64_BITS
typedef __int64 poly_product_t;
#endif

#if !defined(HAS_POLY_PRODUCT_T)
# define HAS_POLY_PRODUCT_T
# if LONG_BIT >= 64 || defined(__LP64__) || defined(_LP64)
#  define POLY_PRODUCT_T_IS_64_BITS
# endif
typedef long poly_product_t;
#endif

/* Longa-Naehrig k = 3, k^-1 = 8193 */
#ifdef POLY_PRODUCT_T_IS_64_BITS
/* k^-5 */
#define NH_INITIATE_K_CORRECTION 11935
#else
/* k^-9 */
#define NH_INITIATE_K_CORRECTION 7278
#endif


#define NH_FLAG_HAS_A 1
#define NH_FLAG_HAS_KEY 2
#define NH_FLAG_HAS_SEED 4
#define NH_FLAG_HAS_RECBITS 8

#define NH_HAS_FLAG(nh, f) ((nh->flags & f) == f)

struct newhope_st {
    NEWHOPE_SIZE size;
    NEWHOPE_ROLE role;
    unsigned int flags;
    unsigned char keyseed[64];
    unsigned char recbits[32];
    int *a;
    int *s;
    int *e;
    int *e2;
    NEWHOPE_A_METHOD a_method;
    unsigned int a_nid;
    unsigned char a_seed[32];

};

typedef unsigned int newhope_poly_512[512];
typedef unsigned int newhope_poly_1024[1024];

#define NH_POLY_SIZE(nhsz) (nhsz)

#define NH_Q 12289

/* TODO consider renaming NH_* to NEWHOPE_* */
int NH_poly_ntt(int *a, unsigned int n);
int NH_poly_intt(int *a, unsigned int n);
void NH_poly_scale(int *a, unsigned int n, int c);
void NH_poly_mul(const int *a, const int *b, int *res, unsigned int n);
void NH_poly_muladd(const int *a, const int *b, const int *c, int *res, unsigned int n);
void NH_poly_reduce2(int *a, unsigned int n);
void NH_poly_correct(int *a, unsigned int n);
