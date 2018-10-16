/* apps/nhparam.c */

#include <openssl/opensslconf.h> /* for OPENSSL_NO_NH */
#ifndef OPENSSL_NO_NEWHOPE
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/newhope.h>

# undef PROG
# define PROG    nhparam_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int list_param = 0, badops = 0;
    char *prog;
    int ret = 1;
    BIO *out = NULL;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    prog = argv[0];
    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-list_param") == 0)
        {
        	list_param = 1;
        }else {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
        BIO_printf(bio_err, "%s -list_param\n", prog);
        goto end;
    }

    ERR_load_crypto_strings();

    if (list_param) {
    	NEWHOPE_NAMED_A* param_name_list = NULL;
    	int num_named_a = NEWHOPE_get_a_list(param_name_list, 0);
    	param_name_list = OPENSSL_malloc((int)(sizeof(NEWHOPE_NAMED_A) * num_named_a));
    	NEWHOPE_get_a_list(param_name_list, num_named_a);

    	int i;
    	for(i = 0; i< num_named_a; i++){
    		BIO_printf(out, "%s\n", OBJ_nid2ln(param_name_list[i].name));
    	}
    	OPENSSL_free(param_name_list);
    	ret = 0;
    	goto end;
    }

 end:
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

#else                           /* !OPENSSL_NO_NEWHOPE */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
