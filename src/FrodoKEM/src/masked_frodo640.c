/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: functions for FrodoKEM-640
*           Instantiates "frodo_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api_masked_frodo640.h"
#include "frodo_macrify.h"


// Parameters for "masked_FrodoKEM-640"
#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 2
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT (2*CRYPTO_BYTES)
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES

#ifndef MASKING_ORDER
#define MASKING_ORDER 1
#define N_SHARES (MASKING_ORDER+1)
#endif

#if (PARAMS_NBAR % 8 != 0)
#error You have modified the cryptographic parameters. FrodoKEM assumes PARAMS_NBAR is a multiple of 8.
#endif

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake128
#define masked_shake     shake128_masked
#if defined(PQM4)
    #define randombytes     PQCLEAN_randombytes
#endif

// CDF table
uint32_t CDF_TABLE[13] = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
uint32_t CDF_TABLE_LEN = 13;


#define crypto_kem_keypair            crypto_kem_keypair_masked_Frodo640
#define crypto_kem_enc                crypto_kem_enc_masked_Frodo640
#define crypto_kem_dec                crypto_kem_dec_masked_Frodo640

#include "masked_kem.c"
#include "noise.c"
#if defined(USE_REFERENCE)
#include "frodo_macrify_reference.c"
#else
#include "frodo_macrify.c"
#endif
#include "masking_interface.c"