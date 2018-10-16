#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_NEWHOPE
int main(int argc, char *argv[])
{
    printf("No NEW HOPE support\n");
    return (0);
}
#else
#include <openssl/newhope.h>

static int test_ntt();
static int test_pkc();
static int test_pkc_fail();
static int test_newhope(NEWHOPE_A_METHOD a_method, unsigned int a_nid, int keytype);

int main(int argc, char *argv[])
{
	int ret = 1;

    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    if(!test_newhope(NEWHOPE_A_METHOD_GS_AES, -1, NEWHOPE_PKC_KEYTYPE_BINOMIAL))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_GS_AES, -1, NEWHOPE_PKC_KEYTYPE_GAUSSIAN))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_GS_SHA256, -1, NEWHOPE_PKC_KEYTYPE_BINOMIAL))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_GS_SHA256, -1, NEWHOPE_PKC_KEYTYPE_GAUSSIAN))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT, NID_luke_a, NEWHOPE_PKC_KEYTYPE_BINOMIAL))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT, NID_luke_a, NEWHOPE_PKC_KEYTYPE_GAUSSIAN))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT, NID_leia_a, NEWHOPE_PKC_KEYTYPE_BINOMIAL))
		goto err;
	if(!test_newhope(NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT, NID_leia_a, NEWHOPE_PKC_KEYTYPE_GAUSSIAN))
		goto err;
	
	ret = 0;
	
	//return ret;
	
err:
    ERR_print_errors_fp(stderr);

    EXIT(ret);
    return ret;
}

#include "../crypto/newhope/newhope_locl.h"

int test_ntt()
{
    int a[1024], b[1024];
    unsigned int i, j;
    /* const unsigned int l = 8; */

    if (RAND_pseudo_bytes((unsigned char*)a, sizeof(a)) == -1) {
        return 0;
    }

    /*
    for (i = 0; i < 1024; ++i) {
        a[i] = i;
    }
    */


    for (i = 0; i < 1024; ++i) {
        a[i] = a[i] % NH_Q;
        if (a[i] < 0) {
            a[i] = NH_Q + a[i];
        }
    }

    memcpy(b, a, sizeof(a));

    NH_poly_ntt(a, 1024);
    /* NH_poly_scale(a, 81, 1024); */
#if 0
    for (i = 0; i < 1024; i += l) {
        printf("ntt(a[%d..%d])\t=", i, i + l - 1);
        for (j = 0; j < l; ++j) {
            printf(" %6d", a[i + j]);
        }
        printf("\n");
    }
#endif
    NH_poly_intt(a, 1024);
    /*
    NH_poly_reduce2(a, 1024);
    NH_poly_correct(a, 1024);
    */

    for (i = 0; i < 1024; ++i) {
        a[i] = ((long)a[i] * 6561) % 12289;
        if (a[i] < 0) {
            a[i] += 12289;
        }
    }

    if (memcmp(a, b, sizeof(a)) == 0) {
        return 1;
    } else {
        return 0;
    }

    /*
    for (i = 0; i < 1024; i += l) {
        printf("a[%d..%d]\t=", i, i + l - 1);
        for (j = 0; j < l; ++j) {
            a[i + j] = ((long)a[i + j] * 6561) % 12289;
            if (a[i + j] < 0) {
                a[i + j] += 12289;
            }
            printf(" %6d", a[i + j]);
        }
        printf("\nb[%d..%d]\t=", i, i + l - 1);
        for (j = 0; j < l; ++j) {
            printf(" %6d", b[i + j]);
        }
        printf("\n");
    }
    */
}

int test_pkc()
{
    NEWHOPE *recipient = NULL;
    NEWHOPE *sender = NULL;
    unsigned char aseed[32];
    int b[1024];
    int u[1024];
    int r[1024];
    unsigned char mkey[32];
    unsigned char ctext[32];

    unsigned char sender_key[32];
    unsigned char recipient_key[32];

    recipient = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
    if (recipient == NULL) {
	goto err;
    }

    sender = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_RESPONDER);
    if (sender == NULL) {
	goto err;
    }

    if (!RAND_bytes(aseed, sizeof(aseed))) {
	goto err;
    }

    if (!NEWHOPE_gen_a_GS_AES(recipient, aseed)) {
	goto err;
    }
    if (!NEWHOPE_gen_a_GS_AES(sender, aseed)) {
	goto err;
    }

    NEWHOPE_generate_key_binomial(recipient);
    NEWHOPE_generate_key_binomial(sender);

    if (!NEWHOPE_initiate(recipient, b, 1024)) {
	goto err;
    }

    if (!NEWHOPE_PKC_enc(sender, b, 1024,
			 u, 1024, r, 1024,
			 mkey, sizeof(mkey),
			 ctext, sizeof(ctext),
			 sender_key, sizeof(sender_key))) {
	goto err;
    }

    if (!NEWHOPE_PKC_dec(recipient, u, 1024, r, 1024,
			 NEWHOPE_PKC_KEYTYPE_BINOMIAL,
			 mkey, sizeof(mkey), ctext, sizeof(ctext),
			 recipient_key, sizeof(recipient_key))) {
	goto err;
    }

    if (memcmp(sender_key, recipient_key, 32)) {
	fprintf(stderr, "PKC keys didn't match\n");
	goto err;
    }

    if (recipient != NULL) {
	NEWHOPE_free(recipient);
    }
    if (sender != NULL) {
	NEWHOPE_free(sender);
    }
    return 1;

err:
    if (recipient != NULL) {
	NEWHOPE_free(recipient);
    }
    if (sender != NULL) {
	NEWHOPE_free(sender);
    }
    return 0;
}

int test_pkc_fail()
{
    NEWHOPE *recipient = NULL;
    NEWHOPE *sender = NULL;
    unsigned char aseed[32];
    int b[1024];
    int u[1024];
    int r[1024];
    unsigned char mkey[32];
    unsigned char ctext[32];

    unsigned char sender_key[32];
    unsigned char recipient_key[32];

    unsigned long e;

    recipient = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
    if (recipient == NULL) {
	goto err;
    }

    sender = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_RESPONDER);
    if (sender == NULL) {
	goto err;
    }

    if (!RAND_bytes(aseed, sizeof(aseed))) {
	goto err;
    }

    if (!NEWHOPE_gen_a_GS_AES(recipient, aseed)) {
	goto err;
    }
    if (!NEWHOPE_gen_a_GS_AES(sender, aseed)) {
	goto err;
    }

    NEWHOPE_generate_key_binomial(recipient);
    NEWHOPE_generate_key_binomial(sender);

    if (!NEWHOPE_initiate(recipient, b, 1024)) {
	goto err;
    }

    b[8] += 1;

    if (!NEWHOPE_PKC_enc(sender, b, 1024,
			 u, 1024, r, 1024,
			 mkey, sizeof(mkey),
			 ctext, sizeof(ctext),
			 sender_key, sizeof(sender_key))) {
	goto err;
    }

    if (NEWHOPE_PKC_dec(recipient, u, 1024, r, 1024,
			 NEWHOPE_PKC_KEYTYPE_BINOMIAL,
			 mkey, sizeof(mkey), ctext, sizeof(ctext),
			 recipient_key, sizeof(recipient_key))) {
	fprintf(stderr, "Verification should have failed, but it didn't\n");
	goto err;
    }

    e = ERR_get_error();

    if (ERR_GET_LIB(e) != ERR_LIB_NEWHOPE ||
	ERR_GET_FUNC(e) != NEWHOPE_F_NEWHOPE_PKC_DEC ||
	ERR_GET_REASON(e) != NEWHOPE_R_VERIFICATION_FAILED) {
	fprintf(stderr, "Verification failed, but for the wrong reason\n");
	goto err;
    }

    if (recipient != NULL) {
	NEWHOPE_free(recipient);
    }
    if (sender != NULL) {
	NEWHOPE_free(sender);
    }
    return 1;

err:
    if (recipient != NULL) {
	NEWHOPE_free(recipient);
    }
    if (sender != NULL) {
	NEWHOPE_free(sender);
    }
    return 0;
}

int test_newhope(NEWHOPE_A_METHOD a_method, unsigned int a_nid, int keytype)
{
	NEWHOPE *initiator = NULL, *responder = NULL;
    unsigned char seed[32];
    int b[1024], u[1024], r[1024];
    unsigned char akey[256/8], bkey[256/8];
	printf("Testing %d, %d, %d\n", a_method, a_nid, keytype);
    /*
    if (!test_ntt()) {
        fprintf(stderr, "NTT tests failed\n");
        goto err;
    }
    */

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
	switch(a_method) {
		case NEWHOPE_A_METHOD_GS_AES :
			if (!NEWHOPE_gen_a_GS_AES(initiator, seed)) {
				goto err;
			}
			if (!NEWHOPE_gen_a_GS_AES(responder, seed)) {
				goto err;
			}
			break;
		case NEWHOPE_A_METHOD_GS_SHA256 :
			if (!NEWHOPE_gen_a_GS_SHA256(initiator, seed)) {
				goto err;
			}
			if (!NEWHOPE_gen_a_GS_SHA256(responder, seed)) {
				goto err;
			}
			break;
		case NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT :
			NEWHOPE_set_a_from_nid(initiator, a_nid);
			NEWHOPE_set_a_from_nid(responder, a_nid);
			break;
		default :
			goto err;
	}
	
	switch(keytype) {
		case NEWHOPE_PKC_KEYTYPE_BINOMIAL :
			if (!NEWHOPE_generate_key_binomial(initiator)) {
				goto err;
			}
			if (!NEWHOPE_generate_key_binomial(responder)) {
				goto err;
			}
			break;
		case NEWHOPE_PKC_KEYTYPE_GAUSSIAN :
			if (!NEWHOPE_generate_key_gaussian(initiator)) {
				goto err;
			}
			if (!NEWHOPE_generate_key_gaussian(responder)) {
				goto err;
			}
			break;
	}

    {
        int *a, *s, *e, *e2;
        FILE *fp;

        a = NEWHOPE_get_a(initiator);
        fp = fopen("a_poly", "wb");
        fwrite(a, sizeof(int), 1024, fp);
        fclose(fp);

        NEWHOPE_get_key(initiator, &s, &e, &e2);
        fp = fopen("initiator_key", "wb");
        fwrite(s, sizeof(int), 1024, fp);
        fwrite(e, sizeof(int), 1024, fp);
        fclose(fp);

        NEWHOPE_get_key(responder, &s, &e, &e2);
        fp = fopen("responder_key", "wb");
        fwrite(s, sizeof(int), 1024, fp);
        fwrite(e, sizeof(int), 1024, fp);
        fwrite(e2, sizeof(int), 1024, fp);
        fclose(fp);
    }

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

    if (memcmp(akey, bkey, sizeof(akey))) {
        fprintf(stderr, "Keys did not match\n");
        goto err;
    }

    if (!test_pkc()) {
	goto err;
    }

    if (!test_pkc_fail()) {
	goto err;
    }

    return 1;


err:
    ERR_print_errors_fp(stderr);
    if (initiator != NULL) {
        NEWHOPE_free(initiator);
    }
    if (responder != NULL) {
        NEWHOPE_free(responder);
    }

    return 0;
}
#endif
