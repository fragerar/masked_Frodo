/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for masked_FrodoKEM-1344
*********************************************************************************************/

#ifndef _API_masked_Frodo1344_H_
#define _API_masked_Frodo1344_H_

#include <stdint.h>
#include <stddef.h>


#define CRYPTO_SECRETKEYBYTES  43088     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES  21520     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 21696     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT

// Algorithm name
#define CRYPTO_ALGNAME "masked_FrodoKEM-1344"


int crypto_kem_keypair_masked_Frodo1344(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_masked_Frodo1344(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_masked_Frodo1344(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
void masked_frodo_sample_n(uint16_t *s, const size_t len);
void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);


#endif
