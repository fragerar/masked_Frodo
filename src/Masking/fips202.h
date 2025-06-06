#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

typedef struct {
	uint64_t s_masked[25 * (MASKING_ORDER + 1)];
} keccak_state_masked;

void shake128_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
void shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);

void shake256_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
void shake256_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake256(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);

// #define shake256_init FIPS202_NAMESPACE(_shake256_init)
// void shake256_init(keccak_state *state);
// #define shake256_absorb FIPS202_NAMESPACE(_shake256_absorb)
// void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
// void shake256_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen);
// #define shake256_finalize FIPS202_NAMESPACE(_shake256_finalize)
// void shake256_finalize(keccak_state *state);
// #define shake256_squeezeblocks FIPS202_NAMESPACE(_shake256_squeezeblocks)
// void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
// void shake256_squeezeblocks_masked(uint8_t* out_masked, size_t nblocks, keccak_state_masked* state_masked, size_t outlen);
// #define shake256_squeeze FIPS202_NAMESPACE(_shake256_squeeze)
// void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

void shake128_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);
void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);
void sha3_256_masked(uint8_t h_masked[32 * (N_SHARES)], const uint8_t* in_masked, size_t inlen);
void sha3_512_masked(uint8_t h_masked[64 * (N_SHARES)], const uint8_t* in_masked, size_t inlen);


void secMult(uint64_t* c, uint64_t* a, uint64_t* b);
unsigned long rand32bits(void);

void KeccakF1600_StatePermute_masked(uint64_t state_masked[25 * (N_SHARES)]);
void keccak_absorb_masked(uint64_t s_masked[25 * (N_SHARES)],
                          unsigned int r,
                          const uint8_t* m_masked,
                          size_t mlen,
                          uint8_t p);

#endif