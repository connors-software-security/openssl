#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define NELTS(x) (sizeof(x)/sizeof(x[0]))

int ttymain(void);
int batchmain(void);

int main(int argc, char *argv[])
{
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    if (isatty(STDIN_FILENO)) {
	return ttymain();
    } else {
	return batchmain();
    }
}

int batchmain(void)
{
    NEWHOPE *initiator = NULL;
    unsigned char seed[32];
    int b[1024*2], u[1024*2], r[1024*2];
    unsigned char key[256/8];
    unsigned char peerkey[256/8];

    while (1) {
	initiator = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
	if (initiator == NULL) {
	    goto err;
	}
    
	if (RAND_pseudo_bytes(seed, sizeof(seed)) == -1) {
	    goto err;
	}

	if (fwrite(seed, sizeof(seed), 1, stdout) != 1) {
	    fputs("Short write sending seed\n", stderr);
	    break;
	}
	fflush(stdout);

	if (!NEWHOPE_gen_a_GS_AES(initiator, seed)) {
	    goto err;
	}

	if (!NEWHOPE_generate_key_binomial(initiator)) {
	    goto err;
	}

	if (!NEWHOPE_initiate(initiator, b, NELTS(b))) {
	    goto err;
	}

	if (fwrite(b, sizeof(b), 1, stdout) != 1) {
	    fputs("Short write sending b\n", stderr);
	    break;
	}
	fflush(stdout);

	if (fread(u, sizeof(u), 1, stdin) != 1) {
	    fputs("Short read on u\n", stderr);
	    break;
	}

	if (fread(r, sizeof(r), 1, stdin) != 1) {
	    fputs("short read on r\n", stderr);
	    break;
	}

	if (!NEWHOPE_finish(initiator,
			    u, NELTS(u), r, NELTS(r),
			    key, sizeof(key))) {
	    goto err;
	}

	if (fread(peerkey, sizeof(peerkey), 1, stdin) != 1) {
	    fputs("short read on peerkey\n", stderr);
	    break;
	}

	if (memcmp(peerkey, key, sizeof(key)) != 0) {
	    fputs("Key mismatch\n", stderr);
	    goto err;
	}

	NEWHOPE_free(initiator);
	initiator = NULL;

    }

    if (initiator != NULL) {
        NEWHOPE_free(initiator);
    }
    return 0;
err:
    ERR_print_errors_fp(stderr);
    if (initiator != NULL) {
        NEWHOPE_free(initiator);
    }
    return 1;
}

int ttymain(void)
{
    NEWHOPE *initiator = NULL;
    unsigned char seed[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    int b[1024], u[1024], r[1024];
    unsigned char key[256/8];
    unsigned char bytes[2];
    int i;

    initiator = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
    if (initiator == NULL) {
        goto err;
    }

    if (!NEWHOPE_gen_a_GS_AES(initiator, seed)) {
        goto err;
    }

    if (!NEWHOPE_generate_key_gaussian(initiator)) {
        goto err;
    }

    if (!NEWHOPE_initiate(initiator, b, NELTS(b))) {
        goto err;
    }

    printf("b polynomial:\n");
    for (i = 0; i < NELTS(b); ++i) {
        printf("%02x%02x", (b[i] >> 8) & 0xff, b[i] & 0xff);
        if (i % 16 == 15) {
            putchar('\n');
        }
    }

    printf("enter u polynomial:\n");
    for (i = 0; i < NELTS(u); ++i) {
        int scanres;
        scanres = scanf("%2hhx%2hhx", &bytes[0], &bytes[1]);
        if (scanres != 2) {
            goto err;
        }
        u[i] = ((unsigned int)bytes[0] << 8) | (unsigned int)bytes[1];
        u[i] = (u[i] << (sizeof(u[i])*8 - 16)) >> (sizeof(u[i])*8 - 16);
    }

    printf("enter r polynomial:\n");
    for (i = 0; i < NELTS(r); ++i) {
        int scanres;
        scanres = scanf("%2hhx%2hhx", &bytes[0], &bytes[1]);
        if (scanres != 2) {
            goto err;
        }
        r[i] = ((unsigned int)bytes[0] << 8) | (unsigned int)bytes[1];
        r[i] = (r[i] << (sizeof(r[i])*8 - 16)) >> (sizeof(r[i])*8 - 16);
    }

    if (!NEWHOPE_finish(initiator,
                        u, NELTS(u), r, NELTS(r),
                        key, sizeof(key))) {
        goto err;
    }

    printf("key is:\n");
    for (i = 0; i < sizeof(key); ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");

    NEWHOPE_free(initiator);

    return 0;

err:
    ERR_print_errors_fp(stderr);
    if (initiator != NULL) {
        NEWHOPE_free(initiator);
    }
    return 1;
}
#endif
