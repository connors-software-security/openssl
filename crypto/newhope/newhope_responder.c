#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    NEWHOPE *responder = NULL;
    unsigned char seed[32];
    int b[1024], u[1024], r[1024];
    unsigned char key[256/8];

    while (1) {
	responder = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_RESPONDER);
	if (responder == NULL) {
	    goto err;
	}

	if (fread(seed, sizeof(seed), 1, stdin) != 1) {
	    fputs("Short read receiving  seed\n", stderr);
	    break;
	}

	if (!NEWHOPE_gen_a_GS_AES(responder, seed)) {
	    goto err;
	}

	if (!NEWHOPE_generate_key_binomial(responder)) {
	    goto err;
	}

	if (fread(b, sizeof(b), 1, stdin) != 1) {
	    fputs("Short read receiving b\n", stderr);
	    break;
	}

	if (!NEWHOPE_respond(responder, b, NELTS(b),
			     u, NELTS(u), r, NELTS(r),
			     key, sizeof(key))) {
	    goto err;
	}

	if (fwrite(u, sizeof(u), 1, stdout) != 1) {
	    fputs("Short write sending u\n", stderr);
	    break;
	}
	fflush(stdout);

	if (fwrite(r, sizeof(r), 1, stdout) != 1) {
	    fputs("Short write sending r\n", stderr);
	    break;
	}
	fflush(stdout);

	if (fwrite(key, sizeof(key), 1, stdout) != 1) {
	    fputs("Short write sending key\n", stderr);
	    break;
	}
	fflush(stdout);

	NEWHOPE_free(responder);
	responder=NULL;
    }

    if (responder != NULL) {
        NEWHOPE_free(responder);
    }
    return 0;
err:
    ERR_print_errors_fp(stderr);
    if (responder != NULL) {
        NEWHOPE_free(responder);
    }
    return 1;
}

int ttymain(void)
{
    NEWHOPE *responder = NULL;
    unsigned char seed[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    int b[1024], u[1024], r[1024];
    unsigned char key[256/8];
    unsigned char bytes[2];
    int i;

    responder = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_RESPONDER);
    if (responder == NULL) {
        goto err;
    }

    if (!NEWHOPE_gen_a_GS_AES(responder, seed)) {
        goto err;
    }

    if (!NEWHOPE_generate_key_gaussian(responder)) {
        goto err;
    }

    printf("enter b polynomial:");
    for (i = 0; i < NELTS(b); ++i) {
        int scanres;
        scanres = scanf("%2hhx%2hhx", &bytes[0], &bytes[1]);
        if (scanres != 2) {
            goto err;
        }
        b[i] = ((unsigned int)bytes[0] << 8) | (unsigned int)bytes[1];
        b[i] = (b[i] << (sizeof(b[i])*8 - 16)) >> (sizeof(b[i])*8 - 16);
    }

    printf("b polynomial:\n");
    for (i = 0; i < NELTS(b); ++i) {
        printf("%02x%02x", (b[i] >> 8) & 0xff, b[i] & 0xff);
        if (i % 16 == 15) {
            putchar('\n');
        }
    }


    if (!NEWHOPE_respond(responder, b, NELTS(b),
                         u, NELTS(u), r, NELTS(r),
                         key, sizeof(key))) {
        goto err;
    }

    printf("u polynomial:\n");
    for (i = 0; i < NELTS(u); ++i) {
        printf("%02x%02x", (u[i] >> 8) & 0xff, u[i] & 0xff);
        if (i % 16 == 15) {
            putchar('\n');
        }
    }

    printf("r polynomial:\n");
    for (i = 0; i < NELTS(r); ++i) {
        printf("%02x%02x", (r[i] >> 8) & 0xff, r[i] & 0xff);
        if (i % 16 == 15) {
            putchar('\n');
        }
    }

    printf("key is:\n");
    for (i = 0; i < sizeof(key); ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;

err:
    ERR_print_errors_fp(stderr);
    if (responder != NULL) {
        NEWHOPE_free(responder);
    }
    return 1;
}
#endif
