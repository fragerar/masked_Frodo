/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test masked_FrodoKEM-1344
*********************************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#if !defined(PQM4) && defined(BENCH)
    #include "ds_benchmark.h"
#endif
#include "../src/api_masked_frodo1344.h"
#include "../src/config.h"


#define SYSTEM_NAME    "masked_FrodoKEM-1344"

#define crypto_kem_keypair            crypto_kem_keypair_masked_Frodo1344
#define crypto_kem_enc                crypto_kem_enc_masked_Frodo1344
#define crypto_kem_dec                crypto_kem_dec_masked_Frodo1344
#define shake                         shake256
#if defined(PQM4)
    #define randombytes     PQCLEAN_randombytes
#endif

#if defined(USE_SHAKE128_FOR_A)
#include "KAT1344_shake.c"
#else
#include "KAT1344.c"
#endif
#include "simple_tests.c"