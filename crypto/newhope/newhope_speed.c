#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_NEWHOPE
int main(int argc, char *argv[])
{
    printf("No NEW HOPE support\n");
    return (0);
}
#else
#include <openssl/newhope.h>


#define NTT_ITERS (2000000)

#define CHECK_RESULTS 0

#undef SAMPLE_GAUSSIAN

#ifdef SAMPLE_GAUSSIAN
#define N_ITERS (30000)
#else
#define N_ITERS (60000)
#endif

#if defined(_POSIX_CPUTIME) && _POSIX_CPUTIME > 0
#define TIMER_DECLS struct timespec start, end
#define TIMER_START() clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start)
#define TIMER_STOP() clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end)
#define TIMER_ELAPSED() ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9)
#else
#define TIMER_DECLS clock_t start, end
#define TIMER_START() start = clock()
#define TIMER_STOP() end = clock()
#define TIMER_ELAPSED() ((double)(end - start)/CLOCKS_PER_SEC)
#endif

void NH_poly_ntt(int *a, unsigned int n);
void NH_poly_intt(int *a, unsigned int n);

void time_ntt(NEWHOPE *initiator)
{
    int a[1024];
    int iter;
    double elapsed;
    TIMER_DECLS;

    memcpy(a, NEWHOPE_get_a(initiator), 1024*sizeof(int));

    TIMER_START();
    for (iter = 0; iter < NTT_ITERS; ++iter) {
        NH_poly_ntt(a, 1024);
    }
    TIMER_STOP();

    elapsed = TIMER_ELAPSED();
    printf("Took %g seconds for %d iterations: %g NTT/sec\n",
           elapsed, NTT_ITERS, NTT_ITERS/elapsed);

    TIMER_START();
    for (iter = 0; iter < NTT_ITERS; ++iter) {
        NH_poly_intt(a, 1024);
    }
    TIMER_STOP();

    elapsed = TIMER_ELAPSED();
    printf("Took %g seconds for %d iterations: %g INTT/sec\n",
           elapsed, NTT_ITERS, NTT_ITERS/elapsed);
}

int main(int argc, char *argv[])
{
    NEWHOPE *initiator = NULL, *responder = NULL;
    unsigned char seed[32];
    int b[1024], u[1024], r[1024];
    unsigned char akey[256/8], bkey[256/8];
    int ret = 1;
    TIMER_DECLS;
    double elapsed;
    int iter;

    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    initiator = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
    if (initiator == NULL) {
        goto err;
    }
    responder = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_RESPONDER);
    if (responder == NULL) {
        goto err;
    }

    if (!RAND_bytes(seed, sizeof(seed))) {
        goto err;
    }

    if (!NEWHOPE_gen_a_GS_AES(initiator, seed)) {
        goto err;
    }
    if (!NEWHOPE_gen_a_GS_AES(responder, seed)) {
        goto err;
    }

#if 0
    time_ntt(initiator);
#endif

    TIMER_START();
    for (iter = 0; iter < N_ITERS; ++iter) {
#ifdef SAMPLE_GAUSSIAN
        if (!NEWHOPE_generate_key_gaussian(initiator)) {
            goto err;
        }
#else
        if (!NEWHOPE_generate_key_binomial(initiator)) {
            goto err;
        }
#endif

#ifdef SAMPLE_GAUSSIAN
        if (!NEWHOPE_generate_key_gaussian(responder)) {
            goto err;
        }
#else
        if (!NEWHOPE_generate_key_binomial(responder)) {
            goto err;
        }
#endif

        if (!NEWHOPE_initiate(initiator, b, 1024)) {
            goto err;
        }
        if (!NEWHOPE_respond(responder, b, 1024,
                             u, 1024, r, 1024,
                             bkey, sizeof(bkey))) {
            goto err;
        }
        if (!NEWHOPE_finish(initiator,
                            u, 1024, r, 1024,
                            akey, sizeof(akey))) {
            goto err;
        }
#if CHECK_RESULTS
        if (memcmp(akey, bkey, sizeof(akey))) {
            fprintf(stderr, "Keys did not match at iter %d\n", iter);
            goto err;
        }
#endif
    }
    TIMER_STOP();

    elapsed = TIMER_ELAPSED();
    printf("Took %g seconds for %d iterations: %g exchanges/sec\n",
           elapsed, N_ITERS, N_ITERS/elapsed);

    ret = 0;


err:
    ERR_print_errors_fp(stderr);
    if (initiator != NULL) {
        NEWHOPE_free(initiator);
    }
    if (responder != NULL) {
        NEWHOPE_free(responder);
    }

    EXIT(ret);
    return ret;
}
#endif
