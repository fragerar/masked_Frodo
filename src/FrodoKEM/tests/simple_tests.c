#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../sha3/fips202.h"

#if defined(PQM4)
    #include "hal.h"
    #include "sendfn.h"
static int printf(const char *format, ...)
{
    hal_send_str(format);
    return 1;
}
int randombytes(uint8_t* buf, size_t xlen);

#else
#include "../random/random.h"
    #include <stdio.h>
    #if BENCH
    #include "ds_benchmark.h"
    #endif 
#endif


#ifndef KEM_TEST_ITERATIONS
    #define KEM_TEST_ITERATIONS 10
#endif


static int kem_test(int iterations) 
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ss_encap[CRYPTO_BYTES], ss_decap[CRYPTO_BYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char bytes[4];
    uint32_t* pos = (uint32_t*)bytes;
    // uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];



    printf("\n");
    printf("=============================================================================================================================\n");
    #if defined(PQM4)
    printf("Testing correctness of key encapsulation mechanism (KEM), system "SYSTEM_NAME"\n");
    send_unsigned("Number of iterations: ", iterations);
    send_unsigned("Masking order: ", MASKING_ORDER);
    #else
    printf("Testing correctness of key encapsulation mechanism (KEM), system "SYSTEM_NAME"\n Number of iterations: %i\n", iterations);
    printf("Masking order: %i\n", MASKING_ORDER);
    #endif
    printf("=============================================================================================================================\n");

    for (int i = 0; i < iterations; i++) {
        if (crypto_kem_keypair(pk, sk) != 0) {
            printf("\n ERROR -- key generation failed!\n");
            return false;
        }
        if (crypto_kem_enc(ct, ss_encap, pk) != 0) {
            printf("\n ERROR -- encapsulation mechanism failed!\n");
            return false;
        }
        crypto_kem_dec(ss_decap, ct, sk);

        if (memcmp(ss_encap, ss_decap, CRYPTO_BYTES) != 0) {
            printf("\n ERROR -- encapsulation/decapsulation mechanism failed!\n");
	        return false; 
        }
    }
    
    // Testing decapsulation after changing random bits of a random 16-bit digit of ct
    randombytes(bytes, 4);
    *pos %= CRYPTO_CIPHERTEXTBYTES/2;
    if (*pos == 0) {
        *pos = 1;
    }
    ((uint16_t*)ct)[*pos] ^= *pos;
    crypto_kem_dec(ss_decap, ct, sk);


    // Compute ss = F(ct || s) with modified ct
    // memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
    // memcpy(&Fin[CRYPTO_CIPHERTEXTBYTES], sk, CRYPTO_BYTES);
    // shake(ss_encap, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);
    
    if (memcmp(ss_encap, ss_decap, CRYPTO_BYTES) == 0) {
        printf("\n ERROR -- changing random bits of the ciphertext should cause a failure!\n");
        return false;
    }
    
    printf("Tests PASSED. All session keys matched.\n");
    printf("\n\n");

    return true;
}

#if !defined(PQM4) && defined(BENCH)

static int64_t cpucycles(void)
{ 
  unsigned int hi, lo;
  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);

}

static void kem_bench() 
{
    int iter = 10;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ss_encap[CRYPTO_BYTES], ss_decap[CRYPTO_BYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

    crypto_kem_keypair(pk, sk);   
    crypto_kem_enc(ct, ss_encap, pk);

    uint64_t start, stop;

    start = cpucycles();
    for(int i=0; i < iter; ++i){
        crypto_kem_dec(ss_decap, ct, sk);
    }
    stop = cpucycles();
    printf("Avg kcycles: %llu\n", (stop-start)/(1000*iter));

}

#endif /* !defined(PQM4) && defined(BENCH) */

static void test_KAT(){

#if defined (USE_SHAKE128_FOR_A)
    printf("KAT using shake\n");
#endif
    unsigned char ss1[CRYPTO_BYTES];
    crypto_kem_dec(ss1, ct_KAT, sk_KAT);
    for(int i=0; i < CRYPTO_BYTES; i++){  

    #if defined(PQM4)
        send_unsigned("SS[i]: ", ss1[i]);
        send_unsigned("SSKAT[i]: ", ss_KAT[i]);
    #else    
        printf("%X", ss1[i]);
    #endif
      if (ss_KAT[i] != ss1[i]){
        printf("KAT failed\n");
        return;
      }
    }
    printf("\n");
    printf("KAT success\n");

}




int main(){
#ifndef BENCH
#if !defined(PROF) && !defined(DO_VALGRIND_CHECK)
  int OK;
  OK = kem_test(KEM_TEST_ITERATIONS);
  printf("Simple test: %i\n", OK);
#endif
  test_KAT();
#else
#ifndef PQM4 
  kem_bench();
  bench_AS_plus_E();
  bench_SHAKE();
  bench_CT_SELECT();
  bench_SAMPLER();
#endif
#endif
  return 1;
}