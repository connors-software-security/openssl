/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef HEADER_NEWHOPE_H
# define HEADER_NEWHOPE_H

# ifdef OPENSSL_NO_NEWHOPE
#  error NEWHOPE is disabled.
# else
# define OPENSSL_NEWHOPE
# endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct newhope_st NEWHOPE;
typedef struct {
	unsigned int name;
	const int * a_poly;
} NEWHOPE_NAMED_A;

typedef enum {
    NEWHOPE_ROLE_INITIATOR,
    NEWHOPE_ROLE_RESPONDER
} NEWHOPE_ROLE;

typedef enum {
    NEWHOPE_512 = 512,
    NEWHOPE_1024 = 1024
} NEWHOPE_SIZE;

#define NEWHOPE_PKC_KEYTYPE_BINOMIAL 0
#define NEWHOPE_PKC_KEYTYPE_GAUSSIAN 1


typedef enum {
    NEWHOPE_A_METHOD_GS_AES = 1,
    NEWHOPE_A_METHOD_GS_SHA256,
    NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT
} NEWHOPE_A_METHOD;

#define NH_A_METHOD_COUNT 3

NEWHOPE *NEWHOPE_new(NEWHOPE_SIZE size, NEWHOPE_ROLE role);
void NEWHOPE_free(NEWHOPE *nh);

NEWHOPE_SIZE NEWHOPE_get_size(NEWHOPE *nh);

/*
 * Set the key material for this newhope instance. The actual values are copied
 * into the instance so the caller retains ownership of the arguments' memory.
 * The e2 value is used only by the responder and should be left as NULL when
 * the role is the initiator.
 */
void NEWHOPE_set_key(NEWHOPE *nh, int *s, int *e, int *e2);

/*
 * Return the method (from NEWHOPE_A_METHOD) used to generate the a value in
 * this newhope instance. Returns 0 if none has been selected.
 */
int NEWHOPE_get_a_method(NEWHOPE *nh);

/*
 * Set NEWHOPE_A_METHOD to be used to generate the a value in this newhope instance.
 */
void NEWHOPE_set_a_method(NEWHOPE *nh, NEWHOPE_A_METHOD a_method);

/*
 * Set the a polynomial used for this newhope instance from memory. The actual values are
 * copied into the instance so the caller retains ownership of the argument's
 * memory.  Set a method equal to NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT.
 */
void NEWHOPE_set_a(NEWHOPE *nh, const int *a);

/*
 * Set the a polynomial for this newhope instance using the NID.
 * Set a method equal to NEWHOPE_A_METHOD_EXPLICIT_BITREV_NTT.
 */
void NEWHOPE_set_a_from_nid(NEWHOPE *nh, int nid);

 /*
  * Set NID when named a used.
  */
 void NEWHOPE_set_a_nid(NEWHOPE* nh, unsigned int nid);

 /*
  * Get NID for a named a polynomial.
  */
 unsigned int NEWHOPE_get_a_nid(NEWHOPE* nh);

/*
 * Get the seed used to generate a for this newhope instance.
 * Returns 1 if a seed was used to generate a, the seed is copied into
 * the seed parameter. Returns 0 if there is not a seed either because
 * no a has been generated or it was specified without a seed.
 */
int NEWHOPE_get_a_seed(NEWHOPE *nh, unsigned char seed[32]);

int *NEWHOPE_get_a(NEWHOPE *nh);

int NEWHOPE_copy_a(NEWHOPE *dest, const NEWHOPE *src);

/*
 * Get list of named a options.  Returns number of options.
 * If nitems = 0 return the number of values on list.
 * Otherwise return the minimum of nitems and length of list.
*/
int NEWHOPE_get_a_list(NEWHOPE_NAMED_A* a_list, int nitems);

void NEWHOPE_get_key(NEWHOPE *nh, int **s, int **e, int **e2);

/*
 * Generate an a value using SHA-256 as in
 * "Speeding up R-LWE post-quantum key exchange" by S. Gueron and F. Schlieker
 */
int NEWHOPE_gen_a_GS_SHA256(NEWHOPE *nh, unsigned char seed[32]);

/*
 * Generate an a value using AES as in
 * "Speeding up R-LWE post-quantum key exchange" by S. Gueron and F. Schlieker
 */
int NEWHOPE_gen_a_GS_AES(NEWHOPE *nh, unsigned char seed[32]);

/*
 * Generate secret key material using discrete gaussian sampling. Sigma is
 * fixed at 8/sqrt(2pi).
 */
int NEWHOPE_generate_key_gaussian(NEWHOPE *nh);

/*
 * Generate secret key material using a cenetered binomial distribution with
 * parameter k=16.
 */
int NEWHOPE_generate_key_binomial(NEWHOPE *nh);

/*
 * Initiate a newhope key exchange. Fills b that must be sent to the responder.
 */
int NEWHOPE_initiate(NEWHOPE *nh, int *b, unsigned b_len);

/*
 * Respond to a newhope key exchange. Accepts the b value sent by the
 * initiator and fills u and r.
 */
int NEWHOPE_respond(NEWHOPE *nh,
                    const int *b, unsigned b_len,
                    int *u, unsigned u_len,
                    int *r, unsigned r_len,
                    unsigned char *shared_key, unsigned key_len);

/*
 * Finalize a newhope key exchange as the initiator. Accepts the u and r
 * from the responder and produces the final shared key.
 */
int NEWHOPE_finish(NEWHOPE *nh,
                   const int *u, unsigned u_len,
                   const int *r, unsigned r_len,
                   unsigned char *shared_key, unsigned key_len);

int NEWHOPE_PKC_enc(NEWHOPE *nh,
		    const int *b, unsigned b_len,
		    int *u, unsigned u_len,
		    int *r, unsigned r_len,
		    unsigned char *mkey, unsigned mkey_len,
		    unsigned char *out, unsigned out_len,
		    unsigned char *shared_key, unsigned key_len);

int NEWHOPE_PKC_dec(NEWHOPE *nh,
		    const int *u, unsigned u_len,
                    const int *r, unsigned r_len,
		    int keytype,
		    const unsigned char *mkey, unsigned mkey_len,
		    const unsigned char *in, unsigned in_len,
		    unsigned char *out, unsigned out_len);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_NEWHOPE_strings(void);

/* Error codes for the NEWHOPE functions. */

/* Function codes. */
# define NEWHOPE_F_NEWHOPE_COPY_A                         108
# define NEWHOPE_F_NEWHOPE_FINISH                         100
# define NEWHOPE_F_NEWHOPE_GEN_A_GS_AES                   101
# define NEWHOPE_F_NEWHOPE_GEN_A_GS_SHA256                102
# define NEWHOPE_F_NEWHOPE_INITIATE                       103
# define NEWHOPE_F_NEWHOPE_NEW                            104
# define NEWHOPE_F_NEWHOPE_PKC_DEC                        105
# define NEWHOPE_F_NEWHOPE_PKC_ENC                        106
# define NEWHOPE_F_NEWHOPE_RESPOND                        107
# define NEWHOPE_F_NEWHOPE_SET_A_METHOD                   109

/* Reason codes. */
# define NEWHOPE_R_512_HELP_REC                           100
# define NEWHOPE_R_BAD_AMETHOD                            110
# define NEWHOPE_R_BAD_KEYTYPE                            101
# define NEWHOPE_R_INVALID_SIZE                           102
# define NEWHOPE_R_MISSING_A                              103
# define NEWHOPE_R_MISSING_KEY                            104
# define NEWHOPE_R_REQUIRES_KEYGEN                        105
# define NEWHOPE_R_SAMPLE_FAILURE                         106
# define NEWHOPE_R_SIZE_MISMATCH                          107
# define NEWHOPE_R_VERIFICATION_FAILED                    108
# define NEWHOPE_R_WRONG_ROLE                             109

# ifdef  __cplusplus
}
# endif
#endif
