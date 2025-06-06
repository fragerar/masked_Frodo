/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for masked_FrodoKEM-640
*********************************************************************************************/

#ifndef _API_masked_Frodo640_H_
#define _API_masked_Frodo640_H_

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_SECRETKEYBYTES  19888     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES   9616     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              16
#define CRYPTO_CIPHERTEXTBYTES  9752     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT

// Algorithm name
#define CRYPTO_ALGNAME "masked_FrodoKEM-640"


int crypto_kem_keypair_masked_Frodo640(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_masked_Frodo640(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_masked_Frodo640(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
void masked_frodo_sample_n(uint16_t *s, const size_t len);
void shake128_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);


#endif
