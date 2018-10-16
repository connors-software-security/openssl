#include "newhope_locl.h"
#include "newhope_a.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "e_os.h"
#include "constant_time_locl.h"

#ifdef OPENSSL_FIPS
# define SHA256_Init private_SHA256_Init
#endif

#define GAUSS_METHOD_MULTISUB 1
#define GAUSS_METHOD_MULTILT 2

#define GAUSS_METHOD GAUSS_METHOD_MULTISUB

/* return 0xff..ff iff x < y; given x and y do not have the high bit set */
static unsigned int constant_time_small_lt(unsigned int x, unsigned int y)
{
    return constant_time_msb(x - y);
}

/* return 0xff..ff iff x <= y; given x and y do not have the high bit set */
static unsigned int constant_time_small_le(unsigned int x, unsigned int y)
{
    return ~constant_time_small_lt(y, x);
}

NEWHOPE *NEWHOPE_new(NEWHOPE_SIZE size, NEWHOPE_ROLE role)
{
    NEWHOPE *ret;
    size_t polysz;

    switch (size) {
#if NEWHOPE_SUPPORT_512
        case NEWHOPE_512:
            polysz = sizeof(newhope_poly_512);
            break;
#endif
        case NEWHOPE_1024:
            polysz = sizeof(newhope_poly_1024);
            break;
        default:
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_NEW, NEWHOPE_R_INVALID_SIZE);
            return NULL;
    }

    ret = (NEWHOPE *)OPENSSL_malloc(sizeof(NEWHOPE));
    if (ret == NULL) {
        goto err;
    }

    ret->a_method = 0;
    ret->size = size;
    ret->role = role;
    ret->flags = 0;
    ret->a_nid = 0;
    ret->a = OPENSSL_malloc(polysz);
    if (ret->a == NULL) {
        goto err;
    }
    ret->s = OPENSSL_malloc(polysz);
    if (ret->s == NULL) {
        goto err;
    }
    ret->e = OPENSSL_malloc(polysz);
    if (ret->e == NULL) {
        goto err;
    }
    if (role == NEWHOPE_ROLE_RESPONDER) {
        ret->e2 = OPENSSL_malloc(polysz);
        if (ret->e2 == NULL) {
            goto err;
        }
    } else {
        ret->e2 = NULL;
    }

    return ret;

err:
    if (ret != NULL) {
        if (ret->a != NULL) {
            OPENSSL_free(ret->a);
        }
        if (ret->s != NULL) {
            OPENSSL_free(ret->s);
        }
        if (ret->e != NULL) {
            OPENSSL_free(ret->e);
        }
        if (ret->e2 != NULL) {
            OPENSSL_free(ret->e2);
        }
        OPENSSL_free(ret);
    }

    NEWHOPEerr(NEWHOPE_F_NEWHOPE_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
};

NEWHOPE_SIZE NEWHOPE_get_size(NEWHOPE *nh)
{
    return nh->size;
}

void NEWHOPE_free(NEWHOPE *nh)
{
    size_t poly_len = 0;

    if (nh == NULL)
        return;

    switch (nh->size) {
    case NEWHOPE_512:
        poly_len = sizeof(newhope_poly_512);
        break;
    case NEWHOPE_1024:
        poly_len = sizeof(newhope_poly_1024);
        break;
    default:
        assert(0);
    }

    if (nh->a != NULL) {
        OPENSSL_free(nh->a);
    }
    if (nh->s != NULL) {
        OPENSSL_cleanse(nh->s, poly_len);
        OPENSSL_free(nh->s);
    }
    if (nh->e != NULL) {
        OPENSSL_cleanse(nh->e, poly_len);
        OPENSSL_free(nh->e);
    }
    if (nh->e2 != NULL) {
        OPENSSL_cleanse(nh->e2, poly_len);
        OPENSSL_free(nh->e2);
    }
    OPENSSL_cleanse(nh->keyseed, sizeof(nh->keyseed));
    OPENSSL_free(nh);
}

/* wouldn't it be nice if this optimized to a single wide store */
static inline void store_le32(unsigned char *buf, unsigned int x) {
    buf[0] = (x >> 0);
    buf[1] = (x >> 8);
    buf[2] = (x >> 16);
    buf[3] = (x >> 24);
}

int NEWHOPE_gen_a_GS_SHA256(NEWHOPE *nh, unsigned char seed[32])
{
    SHA256_CTX sha;
    unsigned int i = 0;
    unsigned int counter;
    unsigned char msg[32+4];
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int sample, samplenr;

    nh->flags &= ~NH_FLAG_HAS_A;
    nh->a_method = 0;

    memcpy(msg, seed, 32);
    for (counter = 0; counter < 0xffffffff; counter++) {
        /* GS actually use SHA3-256, but OpenSSL doesn't have SHA3 so we
         * use SHA2-256 instead */
        SHA256_Init(&sha);
        store_le32(&msg[32], counter);
        SHA256_Update(&sha, msg, sizeof(msg));
        SHA256_Final(md, &sha);
        for (samplenr = 0; samplenr < SHA256_DIGEST_LENGTH / 2; samplenr++) {
            /* byte order doesn't actually matter here */
            sample = ((unsigned int)md[samplenr * 2]) | 
                (((unsigned int)md[samplenr * 2 + 1]) << 8);
            /* TODO - benchmark which sampling method is actually faster */
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample < NH_Q) {
                nh->a[i++] = sample;
                if (i == NH_POLY_SIZE(nh->size)) {
                    nh->flags |= NH_FLAG_HAS_A;
                    nh->a_method = NEWHOPE_A_METHOD_GS_SHA256;
                    memcpy(nh->a_seed, seed, 32);
                    return 1;
                }
            }
        }
    }

    NEWHOPEerr(NEWHOPE_F_NEWHOPE_GEN_A_GS_SHA256,
               NEWHOPE_R_SAMPLE_FAILURE);

    return 0;
}

int NEWHOPE_gen_a_GS_AES(NEWHOPE *nh, unsigned char seed[32])
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    EVP_CIPHER_CTX c_ctx;
    unsigned char in[8*AES_BLOCK_SIZE], out[8*AES_BLOCK_SIZE];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int sample, samplenr;
    unsigned int i = 0;
    int ok;
    int outl;

    nh->flags &= ~NH_FLAG_HAS_A;
    nh->a_method = 0;

    /* GS actually use SHA3-256, but OpenSSL doesn't have SHA3 so we
     * use SHA2-256 instead */
    SHA256(seed, 32, md);

    EVP_CIPHER_CTX_init(&c_ctx);
    memset(ivec, 0, sizeof(ivec));

    if (!EVP_EncryptInit_ex(&c_ctx, EVP_aes_256_ctr(), NULL, md, ivec)) {
        EVP_CIPHER_CTX_cleanup(&c_ctx);
        return 0;
    }

    memset(in, 0, sizeof(in));

    while (ivec[0] != 0xff) {
        ok = EVP_EncryptUpdate(&c_ctx, out, &outl, in, sizeof(in));
        if (!ok || outl != sizeof(out)) {
            return 0;
        }
        for (samplenr = 0; samplenr < sizeof(out) / 2; samplenr++) {
            /* byte order doesn't actually matter here */
            sample = ((unsigned int)out[samplenr * 2]) | 
                (((unsigned int)out[samplenr * 2 + 1]) << 8);
            /* TODO - benchmark which sampling method is actually faster */
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample >= NH_Q) sample -= NH_Q;
            if (sample < NH_Q) {
                nh->a[i++] = sample;
                if (i == NH_POLY_SIZE(nh->size)) {
                    nh->flags |= NH_FLAG_HAS_A;
                    nh->a_method = NEWHOPE_A_METHOD_GS_AES;
                    memcpy(nh->a_seed, seed, 32);
                    EVP_CIPHER_CTX_cleanup(&c_ctx);
                    return 1;
                }
            }
        }
    }

    EVP_CIPHER_CTX_cleanup(&c_ctx);
    NEWHOPEerr(NEWHOPE_F_NEWHOPE_GEN_A_GS_AES,
               NEWHOPE_R_SAMPLE_FAILURE);
    return 0;
}

static int generate_recbits(NEWHOPE *nh, EVP_CIPHER_CTX *c_ctx)
{
    unsigned char in[256/8];
    int ok, outl;

    memset(in, 0, sizeof(in));
    ok = EVP_EncryptUpdate(c_ctx, nh->recbits, &outl,
                           in, sizeof(nh->recbits));
    if (!ok || outl != sizeof(nh->recbits)) {
        return 0;
    }

    nh->flags |= NH_FLAG_HAS_RECBITS;
    return 1;
}

typedef int(*noisefn)(int *, unsigned int, EVP_CIPHER_CTX*);

static inline int generate_key(NEWHOPE *nh, noisefn get_noise) {
    EVP_CIPHER_CTX c_ctx;
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char aeskey[32];
    int res = 0;

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_SEED)) {
	if (!RAND_bytes(nh->keyseed, sizeof(nh->keyseed))) {
	    return 0;
	}
        nh->flags |= NH_FLAG_HAS_SEED;
    }

    memset(ivec, 0, sizeof(ivec));

    EVP_CIPHER_CTX_init(&c_ctx);

    SHA256(nh->keyseed, sizeof(nh->keyseed), aeskey);

    if (!EVP_EncryptInit_ex(&c_ctx, EVP_aes_256_ctr(), NULL, aeskey, ivec)) {
	goto end;
    }

    if (!get_noise(nh->s, nh->size, &c_ctx)) {
	goto end;
    }
    NH_poly_ntt(nh->s, nh->size);

    if (!get_noise(nh->e, nh->size, &c_ctx)) {
	goto end;
    }
    NH_poly_ntt(nh->e, nh->size);

    if (nh->e2 != NULL) {
        if (!get_noise(nh->e2, nh->size, &c_ctx)) {
	    goto end;
        }
        NH_poly_ntt(nh->e2, nh->size);
    }

    if (nh->role == NEWHOPE_ROLE_RESPONDER) {
        if (!generate_recbits(nh, &c_ctx)) {
            goto end;
        }
    }

    nh->flags |= NH_FLAG_HAS_KEY;
    res = 1;
end:
    OPENSSL_cleanse(aeskey, sizeof(aeskey));
    if (!EVP_CIPHER_CTX_cleanup(&c_ctx)) {
	return 0;
    }
    return res;
}

#include "rlwe_table.h"

static inline unsigned int ct_sub_borrow_out(unsigned int x, unsigned int y, unsigned int c)
{
    return constant_time_msb((~x & y) | ((~x | y) & (x - y + c)));
}

static int gaussian_noise(int *p, unsigned int size, EVP_CIPHER_CTX *c_ctx) {
    unsigned char in[AES_BLOCK_SIZE*3];
    unsigned char signbits[AES_BLOCK_SIZE];
    unsigned char samplebits[AES_BLOCK_SIZE*3];
    unsigned char *sample;
    unsigned int i, j, c;
    unsigned int si, sj;
    unsigned int x[6];
    unsigned int sign;
    int outl;
    int s;
    int ok;

    memset(in, 0, sizeof(in));

    si = sj = 0;
    for (i = 0; i < size; i++) {
        if (si == 0) {
	    ok = EVP_EncryptUpdate(c_ctx, signbits, &outl,
				   in, sizeof(signbits));
	    if (!ok || outl != sizeof(signbits)) {
		OPENSSL_cleanse(signbits, sizeof(signbits));
		OPENSSL_cleanse(samplebits, sizeof(samplebits));
		return 0;
	    }
        }
        if (i % 2 == 0) {
            /* this is enough for 2 samples */
	    ok = EVP_EncryptUpdate(c_ctx, samplebits, &outl,
				   in, sizeof(samplebits));
	    if (!ok || outl != sizeof(samplebits)) {
		OPENSSL_cleanse(signbits, sizeof(signbits));
		OPENSSL_cleanse(samplebits, sizeof(samplebits));
		return 0;
	    }
            sample = &samplebits[0];
        } else {
            sample = &samplebits[192/8];
        }
        for (j = 0; j < 6; j++) {
            /* byte order doesn't actually matter here */
            x[j] = (unsigned int)sample[j * 4] |
                ((unsigned int)sample[j * 4 + 1] << 8) |
                ((unsigned int)sample[j * 4 + 2] << 16) |
                ((unsigned int)sample[j * 4 + 3] << 24);
        }
        s = 52;
        for (j = 0; j < 52; j++) {
#if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) \
        && !defined(OPENSSL_NO_INLINE_ASM) \
        && (defined(__x86_64) || defined(__x86_64__) \
            || defined(__i386) || defined(__i386__))
            asm ("mov %[x0],%[tmp]\n\t"
                "sub %[t0],%[tmp]\n\t"
                "mov %[x1],%[tmp]\n\t"
                "sbb %[t1],%[tmp]\n\t"
                "mov %[x2],%[tmp]\n\t"
                "sbb %[t2],%[tmp]\n\t"
                "mov %[x3],%[tmp]\n\t"
                "sbb %[t3],%[tmp]\n\t"
                "mov %[x4],%[tmp]\n\t"
                "sbb %[t4],%[tmp]\n\t"
                "mov %[x5],%[tmp]\n\t"
                "sbb %[t5],%[tmp]\n\t"
                "sbb $0,%[s]"
                : [s] "+rm" (s), [tmp] "=&r" (c)
                : [x0] "rm" (x[0]), [t0] "rm" (rlwe_table[j][0]),
                  [x1] "rm" (x[1]), [t1] "rm" (rlwe_table[j][1]),
                  [x2] "rm" (x[2]), [t2] "rm" (rlwe_table[j][2]),
                  [x3] "rm" (x[3]), [t3] "rm" (rlwe_table[j][3]),
                  [x4] "rm" (x[4]), [t4] "rm" (rlwe_table[j][4]),
                  [x5] "rm" (x[5]), [t5] "rm" (rlwe_table[j][5])
                : "cc");
#elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) \
        && !defined(OPENSSL_NO_INLINE_ASM) \
        && (defined(__arm) || defined(__arm__))
            asm ("ldr %[tmp], %[x0]\n\t"
                 "subs %[tmp], %[tmp], %[t0]\n\t"
                 "ldr %[tmp], %[x1]\n\t"
                 "sbcs %[tmp], %[tmp], %[t1]\n\t"
                 "ldr %[tmp], %[x2]\n\t"
                 "sbcs %[tmp], %[tmp], %[t2]\n\t"
                 "ldr %[tmp], %[x3]\n\t"
                 "sbcs %[tmp], %[tmp], %[t3]\n\t"
                 "ldr %[tmp], %[x4]\n\t"
                 "sbcs %[tmp], %[tmp], %[t4]\n\t"
                 "ldr %[tmp], %[x5]\n\t"
                 "sbcs %[tmp], %[tmp], %[t5]\n\t"
                 "sbc %[s],%[s],0"
                 : [s] "+r" (s), [tmp] "=&r" (c)
                 : [x0] "m" (x[0]), [t0] "r" (rlwe_table[j][0]),
                   [x1] "m" (x[1]), [t1] "r" (rlwe_table[j][1]),
                   [x2] "m" (x[2]), [t2] "r" (rlwe_table[j][2]),
                   [x3] "m" (x[3]), [t3] "r" (rlwe_table[j][3]),
                   [x4] "m" (x[4]), [t4] "r" (rlwe_table[j][4]),
                   [x5] "m" (x[5]), [t5] "r" (rlwe_table[j][5])
                 : "cc");
#else
#if GAUSS_METHOD == GAUSS_METHOD_MULTISUB
            /* do a multi-word subtraction */
            c = ct_sub_borrow_out(x[0], rlwe_table[j][0], 0);
            c = ct_sub_borrow_out(x[1], rlwe_table[j][1], c);
            c = ct_sub_borrow_out(x[2], rlwe_table[j][2], c);
            c = ct_sub_borrow_out(x[3], rlwe_table[j][3], c);
            c = ct_sub_borrow_out(x[4], rlwe_table[j][4], c);
            c = ct_sub_borrow_out(x[5], rlwe_table[j][5], c);
            /* subtract one if underflow (borrow) */
            s -= constant_time_select(c, 1, 0);
#elif GAUSS_METHOD == GAUSS_METHOD_MULTILT
            /* c is the multi-word less-than */
            c = constant_time_lt(x[0], rlwe_table[j][0]);
            c &= constant_time_eq(x[1], rlwe_table[j][1]);
            c |= constant_time_lt(x[1], rlwe_table[j][1]);
            c &= constant_time_eq(x[2], rlwe_table[j][2]);
            c |= constant_time_lt(x[2], rlwe_table[j][2]);
            c &= constant_time_eq(x[3], rlwe_table[j][3]);
            c |= constant_time_lt(x[3], rlwe_table[j][3]);
            c &= constant_time_eq(x[4], rlwe_table[j][4]);
            c |= constant_time_lt(x[4], rlwe_table[j][4]);
            c &= constant_time_eq(x[5], rlwe_table[j][5]);
            c |= constant_time_lt(x[5], rlwe_table[j][5]);
            /* subtract one for each entry >= x */
            s -= constant_time_select(c, 1, 0);
#else
#error Invalid GAUSS_METHOD
#endif
#endif
        }
        /* get 8 bits set in sign, enough for the masking below */
        sign = constant_time_is_zero((signbits[si] >> sj) & 1);
        p[i] = (s ^ sign) - sign;
        sj = (sj + 1) % 8;
        if (sj == 0) {
            si = (si + 1) % sizeof(signbits);
        }
    }

    OPENSSL_cleanse(signbits, sizeof(signbits));
    OPENSSL_cleanse(samplebits, sizeof(samplebits));

    return 1;
}

int NEWHOPE_generate_key_gaussian(NEWHOPE *nh)
{
    return generate_key(nh, gaussian_noise);
}

static inline unsigned int popcnt(unsigned int x) {
    unsigned int r = 0;
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    r = (((x + (x >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
    return r;
}

#define BINOMIAL_BLOCK (512*4)

#if defined(NH_ASM) && \
    (defined(__x86_64) || defined(__x86_64__) \
     || defined(_M_AMD64) || defined(_M_X64))
extern unsigned int OPENSSL_ia32cap_P[];
# define BINOMIAL_ASM_CAPABLE (OPENSSL_ia32cap_P[1]&(1<<(41-32)))
#endif

#ifdef BINOMIAL_ASM_CAPABLE
extern void NEWHOPE_binomial_xform(int *, unsigned char*);
#endif

static int binomial_noise(int *p, unsigned int size, EVP_CIPHER_CTX *c_ctx)
{
    unsigned char in[BINOMIAL_BLOCK];
    unsigned char out[BINOMIAL_BLOCK];
    unsigned int a;
    unsigned int i;
    unsigned int base;
    int outl;
    int ok;

    memset(in, 0, sizeof(in));

    for (base = 0; base < size; base += 512) {
        ok = EVP_EncryptUpdate(c_ctx, out, &outl, in, sizeof(in));
        if (!ok || outl != sizeof(out)) {
            OPENSSL_cleanse(out, sizeof(out));
            return 0;
        }
#ifdef BINOMIAL_ASM_CAPABLE
        if (BINOMIAL_ASM_CAPABLE) {
            NEWHOPE_binomial_xform(&p[base], out);
        } else
#endif
        {
            for (i = 0; i < 512; ++i) {
                a = (out[i * 4 + 0] | (out[i * 4 + 1] << 8)
                    | (out[i * 4 + 2] << 16) | (out[i * 4 + 3] << 24));
                p[base + i] = popcnt(a & 0x0f0f0f0f) - popcnt(a & 0xf0f0f0f0);
            }
        }
    }

    OPENSSL_cleanse(out, sizeof(out));

    return 1;
}

int NEWHOPE_generate_key_binomial(NEWHOPE *nh)
{
    return generate_key(nh, binomial_noise);
}

int NEWHOPE_initiate(NEWHOPE *nh, int *b, unsigned b_len)
{
    if (b_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_INITIATE, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (nh->role != NEWHOPE_ROLE_INITIATOR) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_INITIATE, NEWHOPE_R_WRONG_ROLE);
        return 0;
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_A)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_INITIATE, NEWHOPE_R_MISSING_A);
        return 0;
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_KEY)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_INITIATE, NEWHOPE_R_MISSING_KEY);
        return 0;
    }

    /* k-factors: a 0/0 e 1/5, s 1/5*/
    NH_poly_muladd(nh->a, nh->s, nh->e, b, nh->size);
    /* k-factors: a 0/0 e 2/12, s 1/5 b_poly 3/7 */
    NH_poly_scale(b, nh->size, NH_INITIATE_K_CORRECTION);
    /* k-factors: a 0/0 e 2/12, s 1/5 b_poly -2/-2 */
    NH_poly_reduce2(b, nh->size);
    /* k-factors: a 0/0 e 2/12, s 1/5 b_poly 0/0 */
    NH_poly_correct(b, nh->size);

    return 1;
}

static int ct_abs(int x)
{
    unsigned int m = constant_time_msb(x);
    return (m ^ x) - m;
}

#define NH_CEIL_Q_2 ((NH_Q + 1) / 2)
#define PARAMETER_Q4        3073 
#define PARAMETER_3Q4       9217 
#define PARAMETER_5Q4       15362 
#define PARAMETER_7Q4       21506 
#define PARAMETER_Q2        6145 
#define PARAMETER_3Q2       18434

#define PARAMETER_Q  NH_Q

static int NH_helprec_1024(NEWHOPE *nh, int *r, const int *x)
{
    int b;
    unsigned int i, j;
    int t[4], v0[4], v1[4], k;
    int norm;

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_RECBITS)) {
        if (!RAND_bytes(nh->recbits, sizeof(nh->recbits))) {
            return 0;
        }
    }

    /* r <- HelpRec = CVP_D4(4/q(x+b*g)) mod 4 */
    /* CVP_D4(t) {
     *   v0 <- rpi(t)
     *   v1 <- rpi(t-g)
     *   k <- norm(x-v0) < 1 ? 0 : 1
     *   (a,b,c,d) <- vk (i.e. v0 or v1 depending on k)
     *   return (a,b,c,k) + d*(-1,-1,-1,2)
     * }
     *
     * x = [0, q)
     * so 4x+b*2 = [0, 4(q-1)+2]
     *
     * v0 = rpi(4/q(x+b*g))
     *    = floor(4/q(x+b*g)+1/2)
     *    = floor(1/q(4x+b*2+q/2))
     *    = { 0;  0 <= 4x+b*2+q/2 < q
     *      { 1;  q <= 4x+b*2+q/2 < 2q
     *      { 2; 2q <= 4x+b*2+q/2 < 3q
     *      { 3; 3q <= 4x+b*2+q/2 < 4q
     *      { 4; 4q <= 4x+b*2+q/2 < 5q
     */

    for (i = 0; i < 256; ++i) {
        b = 1 & (nh->recbits[i / 8] >> (i & 0x7));
        t[0] = (4 * x[i +   0] + 2 * b);
        t[1] = (4 * x[i + 256] + 2 * b);
        t[2] = (4 * x[i + 512] + 2 * b);
        t[3] = (4 * x[i + 768] + 2 * b);

        norm = 0;
        for (j = 0; j < 4; ++j) {
            v0[j] = 4
                  + constant_time_small_lt(t[j], (NH_CEIL_Q_2))
                  + constant_time_small_lt(t[j], (NH_Q + NH_CEIL_Q_2))
                  + constant_time_small_lt(t[j], (2 * NH_Q + NH_CEIL_Q_2))
                  + constant_time_small_lt(t[j], (3 * NH_Q + NH_CEIL_Q_2));
            v1[j] = 3
                  + constant_time_small_lt(t[j], (NH_Q))
                  + constant_time_small_lt(t[j], (2 * NH_Q))
                  + constant_time_small_lt(t[j], (3 * NH_Q));
            norm += ct_abs(t[j] - v0[j] * NH_Q);
        }

        k = constant_time_small_lt(norm, NH_Q);
        /* k is either 0 or 0xf; v0[*] and v1[*] in [0,4] */
        v0[0] = (k & (v0[0] ^ v1[0])) ^ v0[0];
        v0[1] = (k & (v0[1] ^ v1[1])) ^ v0[1];
        v0[2] = (k & (v0[2] ^ v1[2])) ^ v0[2];
        v0[3] = (k & (v0[3] ^ v1[3])) ^ v0[3];
        r[i +   0] = (v0[0] - v0[3]) & 0x3;
        r[i + 256] = (v0[1] - v0[3]) & 0x3;
        r[i + 512] = (v0[2] - v0[3]) & 0x3;
        r[i + 768] = ((k & 1) + v0[3] * 2) & 0x3;
    }

    return 1;
}


static void NH_rec_D4_1024(const int *x, const int *r, unsigned char *nu)
{
    unsigned int i, j, m, norm;
    int t[4];

    memset(nu, 0, 256/8);

    for (i = 0; i < 256; ++i) {
        t[0] = 8 * x[i +   0] - (2 * r[i +   0] + r[i + 768]) * NH_Q;
        t[1] = 8 * x[i + 256] - (2 * r[i + 256] + r[i + 768]) * NH_Q;
        t[2] = 8 * x[i + 512] - (2 * r[i + 512] + r[i + 768]) * NH_Q;
        t[3] = 8 * x[i + 768] - r[i + 768] * NH_Q;

        norm = 0;
        for (j = 0; j < 4; ++j) {
            t[j] = t[j] + 4 * NH_Q;
            /* start t[j] %= 8q */
            /* t[j] in [-5q,12q) */
            m = constant_time_msb(t[j]);
            t[j] += constant_time_select(m, 8 * NH_Q, 0);
            /* t[j] in [0,12q) */
            m = constant_time_small_lt(t[j], 8 * NH_Q);
            t[j] -= constant_time_select(m, 0, 8 * NH_Q);
            /* t[j] in [0,8q) */
            /* end t[j] %= 8 */

            t[j] -= 4 * NH_Q;
            norm += ct_abs(t[j]);
        }

        nu[i / 8] |= constant_time_select(constant_time_small_le(norm, 8 * NH_Q), 0, 1) << (i & 7);
    }
}

int NEWHOPE_respond(NEWHOPE *nh,
                    const int *b, unsigned b_len,
                    int *u, unsigned u_len,
                    int *r, unsigned r_len,
                    unsigned char *shared_key, unsigned key_len)
{
    int *v_poly;
    int status = 0;
    unsigned char nu[256/8];

    if (b_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (u_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (r_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (key_len != 256 / 8) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (nh->role != NEWHOPE_ROLE_RESPONDER) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_WRONG_ROLE);
        return 0;
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_A)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_MISSING_A);
        return 0;
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_KEY)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_MISSING_KEY);
        return 0;
    }

    v_poly = OPENSSL_malloc(sizeof(int) * nh->size);
    if (v_poly == NULL) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* k-factors: e 1/5, a 0/0 s 1/5 e2 1/5*/
    NH_poly_muladd(nh->a, nh->s, nh->e, u, nh->size);
    /* k-factors: e 1/5, a 0/0 s 1/5 e2 1/5 u_poly 3/7 */
    NH_poly_scale(u, nh->size, NH_INITIATE_K_CORRECTION);
    /* k-factors: e 2/10, a 0/0 s 1/5 e2 1/5 u_poly -2/-2 */
    NH_poly_reduce2(u, nh->size);
    /* k-factors: e 2/10, a 0/0 s 1/5 e2 1/5 u_poly 0/0 */
    NH_poly_correct(u, nh->size);

    /* k-factors: e 2/10, a 0/0 s 1/5 e2 1/5 u_poly 0/0, b_poly 0/0 */
    NH_poly_muladd(b, nh->s, nh->e2, v_poly, nh->size);
    /* k-factors: e 2/10, a 0/0 s 1/5 e2 1/5 u_poly 0/0, b_poly 0/0, v_poly 3/7 */

    /* k-factors: e 2/8, a 1/6 s 1/6 e2 1/6 u_poly 0/0, b_poly 0/0, v_poly 3/7 */
    NH_poly_intt(v_poly, nh->size);
    /* k-factors: e 2/8, a 1/6 s 1/6 e2 1/6 u_poly 0/0, b_poly 0/0, v_poly -2/-2 */

    NH_poly_reduce2(v_poly, nh->size);
    /* k-factors: e 2/8, a 1/6 s 1/6 e2 1/6 u_poly 0/0, b_poly 0/0, v_poly 0/0 */
    NH_poly_correct(v_poly, nh->size);

    if (nh->size == 1024) {
        if (!NH_helprec_1024(nh, r, v_poly)) {
            status = 0;
            goto end;
        }
        NH_rec_D4_1024(v_poly, r, nu);
        SHA256(nu, sizeof(nu), shared_key);
    } else {
        /* FIXME what to do for 512 */
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_RESPOND, NEWHOPE_R_512_HELP_REC);
        status = 0;
        goto end;
    }

    status = 1;

end:
    OPENSSL_cleanse(nu, sizeof(nu));
    OPENSSL_cleanse(v_poly, sizeof(int) * nh->size);
    OPENSSL_free(v_poly);
    return status;
}

int NEWHOPE_finish(NEWHOPE *nh,
                   const int *u, unsigned u_len,
                   const int *r, unsigned r_len,
                   unsigned char *shared_key, unsigned key_len)
{
    unsigned char nu[256/8];
    int *v_poly;
    int status;

    if (nh->role != NEWHOPE_ROLE_INITIATOR) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, NEWHOPE_R_WRONG_ROLE);
        return 0;
    }

    if (u_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (r_len != nh->size) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (key_len != 256 / 8) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    v_poly = OPENSSL_malloc(nh->size * sizeof(int));
    if (v_poly == NULL) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* k-factors: a 0/0 e 2/7, s 1/5 b_poly 0/0, u_poly 0/0, r_poly 0/0 */
    NH_poly_mul(nh->s, u, v_poly, nh->size);
    /* k-factors: a 0/0 e 2/7, s 1/5 b_poly 0/0, u_poly 0/0, r_poly 0/0, v_poly 3/7 */
    NH_poly_intt(v_poly, nh->size);
    /* k-factors: a 0/0 e 2/7, s 1/5 b_poly 0/0, u_poly 0/0, r_poly 0/0, v_poly -2/-2 */

    NH_poly_reduce2(v_poly, nh->size);
    /* k-factors: a 0/0 e 2/7, s 1/5 b_poly 0/0, u_poly 0/0, r_poly 0/0, v_poly 0/0 */
    NH_poly_correct(v_poly, nh->size);

    if (nh->size == 1024) {
        NH_rec_D4_1024(v_poly, r, nu);
        SHA256(nu, sizeof(nu), shared_key);
    } else {
        /* FIXME what to do for 512 */
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_FINISH, NEWHOPE_R_512_HELP_REC);
        status = 0;
        goto end;
    }

    status = 1;

end:
    OPENSSL_cleanse(nu, sizeof(nu));
    OPENSSL_cleanse(v_poly, nh->size * sizeof(int));
    OPENSSL_free(v_poly);
    return status;
}

void NEWHOPE_set_a(NEWHOPE *nh, const int* a)
{
    unsigned int i;
	for (i = 0; i < nh->size; ++i) {
		nh->a[i] = a[i];
		}
    nh->flags |= NH_FLAG_HAS_A;
    nh->a_method = NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT;
}

void NEWHOPE_set_a_from_nid(NEWHOPE* nh, int nid)
{
	int i, j;
	int num_named_a = (sizeof(nh_named_a_list)/sizeof(nh_named_a_list[0]));

	nh->flags &= ~NH_FLAG_HAS_A;
	nh->a_method = NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT;

	for(i=0; i<num_named_a; i++){
			if(nh_named_a_list[i].name == nid){
				for(j=0; j<(nh->size); j++){
					nh->a[j] = (nh_named_a_list[i].a_poly)[j];
				}

				nh->flags |= NH_FLAG_HAS_A;
				return;
			}
	}
	for(j=0; j<(nh->size); j++){
			nh->a[j] = (nh_named_a_list[0].a_poly)[j];
	}

    nh->flags |= NH_FLAG_HAS_A;
}

int NEWHOPE_get_a_list(NEWHOPE_NAMED_A* a_list, int nitems)
{
	if(nitems == 0){
		return NAMED_A_LIST_LENGTH;

	}

	int min = nitems < NAMED_A_LIST_LENGTH ? nitems : NAMED_A_LIST_LENGTH;

	int i;
	for(i=0; i<min; i++){
		a_list[i].name = nh_named_a_list[i].name;
		a_list[i].a_poly = NULL;

	}
	return min;
}


void NEWHOPE_set_a_nid(NEWHOPE* nh, unsigned int nid){
		nh->a_nid = nid;
}

unsigned int NEWHOPE_get_a_nid(NEWHOPE* nh){
	return nh->a_nid;
}

void NEWHOPE_set_a_method(NEWHOPE *nh, NEWHOPE_A_METHOD a_method){
	switch(a_method) {
	case NEWHOPE_A_METHOD_GS_AES:
	case NEWHOPE_A_METHOD_GS_SHA256:
	case NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT:
		nh->a_method = a_method;
		break;
	default:
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_SET_A_METHOD, NEWHOPE_R_BAD_AMETHOD);

	}
}

int NEWHOPE_get_a_method(NEWHOPE *nh)
{
    return nh->a_method;
}

int NEWHOPE_get_a_seed(NEWHOPE *nh, unsigned char seed[32])
{
    switch (nh->a_method) {
        case NEWHOPE_A_METHOD_GS_AES:
        case NEWHOPE_A_METHOD_GS_SHA256:
            memcpy(seed, nh->a_seed, sizeof(nh->a_seed));
            return 1;
        default:
            return 0;
    }
}

int NEWHOPE_copy_a(NEWHOPE *dest, const NEWHOPE *src)
{
    size_t polysz;

    if (dest->size != src->size) {
        return 0;
    }

    switch (dest->size) {
        case NEWHOPE_512:
            polysz = sizeof(newhope_poly_512);
            break;
        case NEWHOPE_1024:
            polysz = sizeof(newhope_poly_1024);
            break;
        default:
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_COPY_A, NEWHOPE_R_INVALID_SIZE);
            return 0;
    }

    memcpy(dest->a, src->a, polysz);
    memcpy(dest->a_seed, src->a_seed, sizeof(dest->a_seed));
    dest->a_method = src->a_method;
    dest->a_nid = src->a_nid;
    dest->flags &= ~NH_FLAG_HAS_A;
    dest->flags |= src->flags & NH_FLAG_HAS_A;
    return 1;
}

void NEWHOPE_set_key(NEWHOPE *nh, int *s, int *e, int *e2)
{
    unsigned int i;
    for (i = 0; i < nh->size; ++i) {
        nh->s[i] = s[i];
        nh->e[i] = e[i];
        if (nh->e2 != NULL) {
            nh->e2[i] = e2[i];
        }
    }
    nh->flags |= NH_FLAG_HAS_KEY;
}

int *NEWHOPE_get_a(NEWHOPE *nh)
{
    return nh->a;
}

void NEWHOPE_get_key(NEWHOPE *nh, int **s, int **e, int **e2)
{
    if (s != NULL) *s = nh->s;
    if (e != NULL) *e = nh->e;
    if (e2 != NULL) *e2 = nh->e2;
}

int NEWHOPE_PKC_enc(NEWHOPE *nh,
		    const int *b, unsigned b_len,
		    int *u, unsigned u_len,
		    int *r, unsigned r_len,
		    unsigned char *mkey, unsigned mkey_len,
		    unsigned char *out, unsigned out_len,
                    unsigned char *shared_key, unsigned key_len)
{
    unsigned char key[32];
    unsigned char md[32];
    int i;

    if (mkey_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_ENC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (out_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_ENC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (key_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_ENC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_SEED)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_ENC, NEWHOPE_R_REQUIRES_KEYGEN);
    }

    if (!NH_HAS_FLAG(nh, NH_FLAG_HAS_RECBITS)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_ENC, NEWHOPE_R_REQUIRES_KEYGEN);
    }

    if (!NEWHOPE_respond(nh, b, b_len,
                    u, u_len, r, r_len,
                    key, sizeof(key))) {
        return 0;
    }

    SHA256(nh->keyseed, 32, md);

    for (i = 0; i < 32; ++i) {
        mkey[i] = nh->keyseed[i] ^ key[i];
    }

    for (i = 0; i < 32; ++i) {
        out[i] = nh->keyseed[32 + i] ^ md[i];
    }

    memcpy(shared_key, &nh->keyseed[32], 32);

    return 1;
}

int NEWHOPE_PKC_dec(NEWHOPE *nh,
		    const int *u, unsigned u_len,
                    const int *r, unsigned r_len,
                    int keytype,
		    const unsigned char *mkey, unsigned mkey_len,
		    const unsigned char *in, unsigned in_len,
		    unsigned char *out, unsigned out_len)
{
    unsigned char key[32];
    unsigned char md[32];
    NEWHOPE *verifier = NULL;
    unsigned char verifier_mkey[32];
    unsigned char verifier_out[32];
    unsigned char verifier_skey[32];
    int *verifier_data = NULL;
    int *verifier_b, *verifier_u, *verifier_r;
    int i;

    if (mkey_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (in_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    if (out_len != 32) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_SIZE_MISMATCH);
        return 0;
    }

    switch (keytype) {
        case NEWHOPE_PKC_KEYTYPE_BINOMIAL:
        case NEWHOPE_PKC_KEYTYPE_GAUSSIAN:
            break;
        default:
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_BAD_KEYTYPE);
            return 0;
    }

    switch (nh->size) {
        case NEWHOPE_512:
        case NEWHOPE_1024:
            break;
        default:
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_INVALID_SIZE);
            return 0;
    }

    verifier_data = OPENSSL_malloc(nh->size * sizeof(int) * 3);
    if (verifier_data == NULL) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    verifier_b = &verifier_data[0];
    verifier_u = &verifier_data[nh->size];
    verifier_r = &verifier_data[2 * nh->size];


    verifier = NEWHOPE_new(nh->size, NEWHOPE_ROLE_RESPONDER);

    if (verifier == NULL) {
        goto err;
    }

    NEWHOPE_set_a(verifier, nh->a);

    if (!NEWHOPE_finish(nh, u, u_len, r, r_len, key, 32)) {
        goto err;
    }

    for (i = 0; i < 32; ++i) {
        verifier->keyseed[i] = mkey[i] ^ key[i];
    }

    SHA256(verifier->keyseed, 32, md);

    for (i = 0; i < 32; ++i) {
        verifier->keyseed[32 + i] = in[i] ^ md[i];
    }

    verifier->flags |= NH_FLAG_HAS_SEED;

    switch (keytype) {
        case NEWHOPE_PKC_KEYTYPE_BINOMIAL:
            if (!NEWHOPE_generate_key_binomial(verifier)) {
                goto err;
            }
            break;
        case NEWHOPE_PKC_KEYTYPE_GAUSSIAN:
            if (!NEWHOPE_generate_key_gaussian(verifier)) {
                goto err;
            }
            break;
    }

    if (!NEWHOPE_initiate(nh, verifier_b, nh->size)) {
        goto err;
    }

    if (!NEWHOPE_PKC_enc(verifier, verifier_b, nh->size,
                         verifier_u, nh->size,
                         verifier_r, nh->size,
                         verifier_mkey, 32,
                         verifier_out, 32,
                         verifier_skey, 32)) {
        goto err;
    }

    if (memcmp(verifier_u, u, nh->size * 2)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_VERIFICATION_FAILED);
        goto err;
    }

    if (memcmp(verifier_r, r, nh->size * 2)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_VERIFICATION_FAILED);
        goto err;
    }

    if (memcmp(verifier_mkey, mkey, 32)) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PKC_DEC, NEWHOPE_R_VERIFICATION_FAILED);
        goto err;
    }

    memcpy(out, &verifier->keyseed[32], 32);
    OPENSSL_cleanse(verifier_data, nh->size * sizeof(int) * 3);
    OPENSSL_free(verifier_data);
    NEWHOPE_free(verifier);
    return 1;


err:
    if (verifier_data != NULL) {
        OPENSSL_cleanse(verifier_data, nh->size * 2 * 3 + 96);
        OPENSSL_free(verifier_data);
    }
    if (verifier != NULL) {
        NEWHOPE_free(verifier);
    }
    return 0;
}


