#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#include "newhope.h"

int main(int argc, char** argv){
    NEWHOPE *nh = NULL;
    nh = NEWHOPE_new(NEWHOPE_1024, NEWHOPE_ROLE_INITIATOR);
    unsigned char seed[32];
    int i;
    NEWHOPE_gen_a_GS_AES(nh, seed);
    int* a = NEWHOPE_get_a(nh);

    for(i=0; i<1024; i++){
        printf("0x%04X, ", a[i]);
        if(i%8 == 7) printf("\n");
    }
    return 0;
    
}
