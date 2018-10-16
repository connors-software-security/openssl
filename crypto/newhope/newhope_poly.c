/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "newhope_locl.h"

#include <assert.h>

#include <stdio.h>

#include "e_os.h"
#include "constant_time_locl.h"

#if defined(NH_ASM)
#  if defined(OPENSSL_CPUID_OBJ) && (defined(__arm__) || defined(__arm))
#    include "arm_arch.h"
#    if __ARM_MAX_ARCH__ >= 7
#      define NTT_ASM 1
#    endif
#  endif
#  if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#    define NTT_ASM 1
#  endif
#endif


/* kred and kred2x are specialized for q = 12289, thus m = 12 k = 3 */
static inline int kred(poly_product_t c)
{
    poly_product_t c0, c1;
    poly_product_t res;
    c0 = c & 0xfff;
    c1 = c >> 12;
    res = 3 * c0 - c1;
    return res;
}

static inline int kred2x(poly_product_t c)
{
#if defined(POLY_PRODUCT_T_IS_64_BITS)
    poly_product_t c0, c1, c2;
    poly_product_t res;
    c0 = c & 0xfff;
    c1 = (c >> 12) & 0xfff;
    c2 = (c >> 24);
    res = (9 * c0) - (3 * c1) + c2;
    return res;
#else
    /* TODO figure out how/if this can be better */
    return kred(kred(c));
#endif
}

#include "ntt_tables.h"

static const long kredmask[4] = { 0xfff, 0xfff, 0xfff, 0xfff };

#if defined(NTT_ASM)
extern int NEWHOPE_poly_ntt_1024_asm(int*);
extern int NEWHOPE_poly_intt_1024_asm(int*);
#endif

/* NTT algorithm from
 *
 *   Longa, P. and Naehrig, M. Speeding up the Number Theoretic Transform
 *   for Faster Ideal Lattice-Based Cryptography
 *
 *   Adds 1 k-factor with 64bits poly_product_t, 5 k-factors with 32bits
 *   poly_product_t
 */
int NH_poly_ntt(int *a, unsigned int n)
{
    unsigned int k, m, i, j, j1, j2;
    const int *psirev;
    int S, U;
    poly_product_t V;

    switch (n) {
        case 512:
            psirev = psirev_512;
            break;
        case 1024:
#if     defined(NTT_ASM)
            if (NEWHOPE_poly_ntt_1024_asm(a)) {
                return 1;
            }
#endif
            psirev = psirev_1024;
            break;
        default:
            return 0;
    }

    k = n;
    for (m = 1; m < n; m *= 2) {
        k /= 2;
        for (i = 0; i < m; ++i) {
            j1 = 2 * i * k;
            j2 = j1 + k - 1;
            S = psirev[m + i]; /* 14 bits */
            for (j = j1; j <= j2; ++j) {
                U = a[j]; /* n bits */
                V = (poly_product_t)a[j + k] * S; /* n + 14 bits */
#ifdef POLY_PRODUCT_T_IS_64_BITS
                if (m == 128) {
                    U = kred(U); /* max(15, n - 11) bits */
                    V = kred2x(V); /* max(15, max(15, n + 3) - 11) */
                } else {
                    V = kred(V); /* max(15, n + 3) bits */
                }
#else
                if (m == 2 || m == 8 || m == 32 || m == 128 || m == 512) {
                    U = kred(U); /* max(15, n - 11) bits */
                    V = kred2x(V); /* max(15, max(15, n + 3) - 11) */
                } else {
                    V = kred(V); /* max(15, n + 3) bits */
                }
#endif
                a[j] = U + V;
                a[j + k] = U - V;
            }
        }
    }
    return 1;
}

/* INTT algorithm from
 *
 *   Longa, P. and Naehrig, M. Speeding up the Number Theoretic Transform
 *   for Faster Ideal Lattice-Based Cryptography
 */
int NH_poly_intt(int *a, unsigned int n)
{
    unsigned int m, j, j1, h, i, j2, k;
    int S, U, V;
    poly_product_t temp;
    const int *psiinv;
    int ninv, npsiinv;

    switch (n) {
        case 512:
            psiinv = psiinv_512;
            ninv = ninv_512;
            npsiinv = npsiinv_512;
            break;
        case 1024:
#if defined(NTT_ASM)
            if (NEWHOPE_poly_intt_1024_asm(a)) {
                return 1;
            }
#endif
            psiinv = psiinv_1024;
            ninv = ninv_1024;
            npsiinv = npsiinv_1024;
            break;
        default:
            return 0;
    }
    
    k = 1;
    for (m = n; m > 2; m /= 2) {
        j1 = 0;
        h = m / 2;
        for (i = 0; i < h; ++i) {
            j2 = j1 + k - 1;
            S = psiinv[h+i]; /* 14 bits */
            for (j = j1; j <= j2; ++j) {
                U = a[j]; /* n bits */
                V = a[j + k]; /* n bits */
                a[j] = U + V; /* n + 1 bits */
                temp = (poly_product_t)(U - V) * S; /* n + 15 bits */
#ifdef POLY_PRODUCT_T_IS_64_BITS
                if (m == 32) {
                    a[j] = kred(a[j]);
                    a[j + k] = kred2x(temp);
                } else {
                    a[j + k] = kred(temp);
                }
#else
                if (m == 512 || m == 128 || m == 32 || m == 8) {
                    a[j] = kred(a[j]);
                    a[j + k] = kred2x(temp);
                } else {
                    a[j + k] = kred(temp);
                }
#endif
            }
            j1 = j1 + 2*k;
        }
        k *= 2;
    }
    for (j = 0; j < k; ++j) {
        U = a[j];
        V = a[j + k];
        a[j] = kred((poly_product_t)(U + V) * ninv);
        a[j + k] = kred((poly_product_t)(U - V) * npsiinv);
    }
    return 1;
}

void NH_poly_scale(int *a, unsigned int n, int c)
{
    unsigned int i;

    for (i = 0; i < n; ++i) {
        a[i] *= c;
    }
}

/* k-factors NH_poly_mul(n, m, n+m+2) */
void NH_poly_mul(const int *a, const int *b, int *res, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; ++i) {
        res[i] = kred((poly_product_t)a[i]*b[i]);
        res[i] = kred(res[i]);
    }
}

/* k-factors NH_poly_muladd(n, m, n+m, n+m+2, _) */
void NH_poly_muladd(const int *a, const int *b, const int *c, int *res, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; ++i) {
        res[i] = kred((poly_product_t)a[i] * b[i] + c[i]);
        res[i] = kred(res[i]);
    }
}

/* k-factors NH_poly_reduce2(in: n out: n+2) */
void NH_poly_reduce2(int *a, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; ++i) {
        a[i] = kred(a[i]);
        a[i] = kred(a[i]);
    }
}

void NH_poly_correct(int *a, unsigned int n)
{
    unsigned int i;
    int mask;

    for (i = 0; i < n; ++i) {
        mask = constant_time_msb(a[i]);
        a[i] += (NH_Q & mask) - NH_Q;
        mask = constant_time_msb(a[i]);
        a[i] += (NH_Q & mask);
    }
}
