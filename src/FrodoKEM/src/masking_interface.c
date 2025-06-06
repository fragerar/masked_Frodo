#include <stdint.h>
#include <stdio.h>
#include "masking_interface.h"
#include "../../Masking/gadgets.h"
#include "../../Masking/utils.h"
#include "../../Masking/basics.h"



void masked_frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s){
  int i;
  const int SIZE_OUT = PARAMS_NBAR*PARAMS_NBAR;
  const int SIZE_S = PARAMS_N*PARAMS_NBAR;

  for(i = 0; i < N_SHARES; i++){
    frodo_mul_bs(out+i*SIZE_OUT, b, s+i*SIZE_S); 
  }
}

#if defined(MUL_ADD_NAIVE)
void masked_frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, uint16_t *e, const uint8_t *seed_A){
  int i;
  const int SIZE_OUT = PARAMS_NBAR*PARAMS_N;
  const int SIZE_SE = PARAMS_NBAR*PARAMS_N;

  for(i = 0; i < N_SHARES; i++){
    frodo_mul_add_sa_plus_e(out+i*SIZE_OUT, s+i*SIZE_SE, e+i*SIZE_SE, seed_A); 
  }
}
#else
static void masked_frodo_mul_add_expanded_sa_plus_e(uint16_t *out, const uint16_t *s, uint16_t *e, const uint16_t *A, int i){
  int j, q, p; 
  #if !defined(USE_AVX2)
      for (j = 0; j < PARAMS_NBAR; j++) {
          uint16_t sum = 0;
          int16_t sp[8];
          for (p = 0; p < 8; p++) {
              sp[p] = s[j*PARAMS_N + i + p];
          }
          for (q = 0; q < PARAMS_N; q++) {
              sum = e[j*PARAMS_N + q];
              for (p = 0; p < 8; p++) {
                  sum += sp[p] * A[p*PARAMS_N + q];
              }
              e[j*PARAMS_N + q] = sum;
          }
      }
#else  // Using vector intrinsics
      for (j = 0; j < PARAMS_NBAR; j++) {
          __m256i b, sp[8], acc;
          for (p = 0; p < 8; p++) {
              sp[p] = _mm256_set1_epi16(s[j*PARAMS_N + i + p]);
          }
          for (q = 0; q < PARAMS_N; q+=16) {
              acc = _mm256_load_si256((__m256i*)&e[j*PARAMS_N + q]);
              for (p = 0; p < 8; p++) {
                  b = _mm256_load_si256((__m256i*)&A[p*PARAMS_N + q]);
                  b = _mm256_mullo_epi16(b, sp[p]);
                  acc = _mm256_add_epi16(b, acc);
              }
              _mm256_store_si256((__m256i*)&e[j*PARAMS_N + q], acc);
          }
      }
#endif
memcpy((unsigned char*)out, (unsigned char*)e, 2*PARAMS_N*PARAMS_NBAR);
}

void masked_frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, uint16_t *e, const uint8_t *seed_A){
  // int i;
  const int SIZE_OUT = PARAMS_NBAR*PARAMS_N;
  const int SIZE_SE = PARAMS_NBAR*PARAMS_N;

  int i, p; 
  ALIGN_HEADER(32) uint16_t A[PARAMS_N*8] ALIGN_FOOTER(32) = {0};

#if defined(USE_AES128_FOR_A)
#if !defined(USE_OPENSSL)
  uint8_t aes_key_schedule[16*11];
  AES128_load_schedule(seed_A, aes_key_schedule);
#else
  EVP_CIPHER_CTX *aes_key_schedule;
  int len;
  if (!(aes_key_schedule = EVP_CIPHER_CTX_new())) handleErrors();
  if (1 != EVP_EncryptInit_ex(aes_key_schedule, EVP_aes_128_ecb(), NULL, seed_A, NULL)) handleErrors();
#endif
  int j, q;
  // Initialize matrix used for encryption
  ALIGN_HEADER(32) uint16_t Ainit[PARAMS_N*8] ALIGN_FOOTER(32) = {0};
     
  for(j = 0; j < PARAMS_N; j+=8) {
      Ainit[0*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[1*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[2*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[3*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[4*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[5*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[6*PARAMS_N + j + 1] = UINT16_TO_LE(j);
      Ainit[7*PARAMS_N + j + 1] = UINT16_TO_LE(j);
  }

  // Start matrix multiplication
  for (i = 0; i < PARAMS_N; i+=8) {
      // Generate 8 rows of A on-the-fly using AES
      for (q = 0; q < 8; q++) {
          for (p = 0; p < PARAMS_N; p+=8) {
              Ainit[q*PARAMS_N + p] = UINT16_TO_LE(i+q);
          }
      }

      size_t A_len = 8 * PARAMS_N * sizeof(uint16_t);
#if !defined(USE_OPENSSL)
      AES128_ECB_enc_sch((uint8_t*)Ainit, A_len, aes_key_schedule, (uint8_t*)A);
#else   
      if (1 != EVP_EncryptUpdate(aes_key_schedule, (uint8_t*)A, &len, (uint8_t*)Ainit, A_len)) handleErrors();
#endif 
#elif defined (USE_SHAKE128_FOR_A)  // SHAKE128
#if !defined(USE_AVX2)
  uint8_t seed_A_separated[2 + BYTES_SEED_A];
  uint16_t* seed_A_origin = (uint16_t*)&seed_A_separated;
  memcpy(&seed_A_separated[2], seed_A, BYTES_SEED_A);

  // Start matrix multiplication
  for (i = 0; i < PARAMS_N; i+=8) {
      seed_A_origin[0] = UINT16_TO_LE(i + 0);
      shake128((unsigned char*)(A + 0*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 1);
      shake128((unsigned char*)(A + 1*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 2);
      shake128((unsigned char*)(A + 2*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 3);
      shake128((unsigned char*)(A + 3*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 4);
      shake128((unsigned char*)(A + 4*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 5);
      shake128((unsigned char*)(A + 5*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 6);
      shake128((unsigned char*)(A + 6*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
      seed_A_origin[0] = UINT16_TO_LE(i + 7);
      shake128((unsigned char*)(A + 7*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A); 
#else  // Using vector intrinsics
  uint8_t seed_A_separated_0[2 + BYTES_SEED_A];
  uint8_t seed_A_separated_1[2 + BYTES_SEED_A];
  uint8_t seed_A_separated_2[2 + BYTES_SEED_A];
  uint8_t seed_A_separated_3[2 + BYTES_SEED_A];
  uint16_t *seed_A_origin_0 = (uint16_t*)&seed_A_separated_0;
  uint16_t *seed_A_origin_1 = (uint16_t*)&seed_A_separated_1;
  uint16_t *seed_A_origin_2 = (uint16_t*)&seed_A_separated_2;
  uint16_t *seed_A_origin_3 = (uint16_t*)&seed_A_separated_3;
  memcpy(&seed_A_separated_0[2], seed_A, BYTES_SEED_A);
  memcpy(&seed_A_separated_1[2], seed_A, BYTES_SEED_A);
  memcpy(&seed_A_separated_2[2], seed_A, BYTES_SEED_A);
  memcpy(&seed_A_separated_3[2], seed_A, BYTES_SEED_A);

  // Start matrix multiplication
  for (i = 0; i < PARAMS_N; i+=8) {
      // Generate hash output
      // First 4 rows
      seed_A_origin_0[0] = UINT16_TO_LE(i + 0);
      seed_A_origin_1[0] = UINT16_TO_LE(i + 1);
      seed_A_origin_2[0] = UINT16_TO_LE(i + 2);
      seed_A_origin_3[0] = UINT16_TO_LE(i + 3);
      shake128_4x((unsigned char*)(A + 0*PARAMS_N), (unsigned char*)(A + 1*PARAMS_N), (unsigned char*)(A + 2*PARAMS_N), (unsigned char*)(A + 3*PARAMS_N),
                  (unsigned long long)(2*PARAMS_N), seed_A_separated_0, seed_A_separated_1, seed_A_separated_2, seed_A_separated_3, 2 + BYTES_SEED_A);
      // Second 4 rows
      seed_A_origin_0[0] = UINT16_TO_LE(i + 4);
      seed_A_origin_1[0] = UINT16_TO_LE(i + 5);
      seed_A_origin_2[0] = UINT16_TO_LE(i + 6);
      seed_A_origin_3[0] = UINT16_TO_LE(i + 7);
      shake128_4x((unsigned char*)(A + 4*PARAMS_N), (unsigned char*)(A + 5*PARAMS_N), (unsigned char*)(A + 6*PARAMS_N), (unsigned char*)(A + 7*PARAMS_N),
                  (unsigned long long)(2*PARAMS_N), seed_A_separated_0, seed_A_separated_1, seed_A_separated_2, seed_A_separated_3, 2 + BYTES_SEED_A);
#endif
#endif

    for(p = 0; p < N_SHARES; p++){
      masked_frodo_mul_add_expanded_sa_plus_e(out+p*SIZE_OUT, s+p*SIZE_SE, e+p*SIZE_SE, A, i); 
    }
  }

#if defined(USE_AES128_FOR_A)
  AES128_free_schedule(aes_key_schedule);
#endif
}
#endif /* MUL_ADD_NAIVE */

void masked_frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e){
  int i;
  const int SIZE_OUTE = PARAMS_NBAR*PARAMS_NBAR;
  const int SIZE_S = PARAMS_NBAR*PARAMS_N;

  for(i = 0; i < N_SHARES; i++){
    frodo_mul_add_sb_plus_e(out+i*SIZE_OUTE, b, s+i*SIZE_S, e+i*SIZE_OUTE); 
  }

}

void masked_frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b){
  int i;
  const int SIZE = PARAMS_NBAR*PARAMS_NBAR;

  for(i = 0; i < N_SHARES; i++){
    frodo_add(out+i*SIZE, a+i*SIZE, b+i*SIZE); 
  }
}

void masked_frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b){
  int i;
  const int SIZE = PARAMS_NBAR*PARAMS_NBAR;

  for(i = 0; i < N_SHARES; i++){
    frodo_sub(out+i*SIZE, a+i*SIZE, b+i*SIZE); 
  }
}

void half_masked_frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b){
  // out = a - b but a is not masked
 
  int i;
  const int SIZE = PARAMS_NBAR*PARAMS_NBAR;
  uint16_t zero[PARAMS_NBAR*PARAMS_NBAR] = {0};

  frodo_sub(out, a, b); 
  for(i = 1; i < N_SHARES; i++){
    frodo_sub(out+i*SIZE, zero, b+i*SIZE); 
  }
}

void masked_frodo_key_encode(uint16_t *out, const uint16_t *in){
  masked_key_encode(out, in, N_SHARES); 
}
void masked_frodo_key_decode(uint16_t *out, const uint16_t *in){
  masked_key_decode(out, in, N_SHARES); 
}

void masked_frodo_sample_n(uint16_t *s, const size_t len) {
  masked_sample_n(s, len, N_SHARES);
}


void masked_frodo_compare(uint16_t* masked_BBp, uint16_t* Bp, uint16_t* masked_CC, uint16_t* C, uint8_t* masked_selector){
  return masked_compare(masked_BBp, Bp, masked_CC, C, masked_selector, N_SHARES);
}


void masked_ct_select(uint8_t* masked_Fin, const uint8_t* ct, uint8_t* masked_kprime, uint8_t* masked_sks, uint8_t* masked_selector){
  int i, j;
  size_t len = CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES;
  uint8_t temp_x[N_SHARES], temp_sks[N_SHARES], temp_kprime[N_SHARES], inv_masked_selector[N_SHARES];

  for(i=0; i < N_SHARES; ++i){
    inv_masked_selector[i] = masked_selector[i];
  }
  inv_masked_selector[0] = ~inv_masked_selector[0];

  

  for(i=0; i < CRYPTO_CIPHERTEXTBYTES; i++){
    masked_Fin[i] = ct[i];
  }

  for(i=1; i < N_SHARES; ++i){
    for(j=0; j < CRYPTO_CIPHERTEXTBYTES; j++){
      masked_Fin[len*i + j] = 0;
    }
  }

  
  for(i=0; i < CRYPTO_BYTES; ++i){
    for(j=0; j < N_SHARES; ++j){
      temp_x[j] = masked_sks[j*CRYPTO_BYTES + i];
    }
    sec_and_u8(temp_sks, temp_x, masked_selector, N_SHARES);

    for(j=0; j < N_SHARES; ++j){
      temp_x[j] = masked_kprime[j*CRYPTO_BYTES + i];
    }
    sec_and_u8(temp_kprime, temp_x, inv_masked_selector, N_SHARES);

    for(j=0; j < N_SHARES; ++j){
      masked_Fin[len*j + i + CRYPTO_CIPHERTEXTBYTES] = temp_kprime[j]^temp_sks[j];
    }

  }
  

}






// ---------------------------------------------

#ifndef PQM4

static int64_t cpucycles(void)
{ 
  unsigned int hi, lo;
  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);

}


void bench_AS_plus_E(){


    

    ALIGN_HEADER(32) uint16_t masked_BBp[PARAMS_N*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t masked_Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};  
    uint16_t *masked_Ep = (uint16_t *)&masked_Sp[PARAMS_N*PARAMS_NBAR*N_SHARES];              

    uint8_t seed_A[BYTES_SEED_A] = {0xAB,};

    masked_frodo_sample_n(masked_Sp, PARAMS_N*PARAMS_NBAR);

    masked_frodo_sample_n(masked_Ep, PARAMS_N*PARAMS_NBAR);


    int iter = 1000;
    uint64_t start, stop;

    start = cpucycles();
    for(int i=0; i < iter; ++i){
        masked_frodo_mul_add_sa_plus_e(masked_BBp, masked_Sp, masked_Ep, seed_A);
    }
    stop = cpucycles();
    printf("\nBench_AS_plus_E Avg kcycles: %lu\n", (stop-start)/(1000*iter));

}


void bench_SHAKE(){
  uint8_t G2in_masked[(1 + BYTES_SEED_SE)*N_SHARES];
  uint8_t in[(BYTES_PKHASH + BYTES_MU + BYTES_SALT)*N_SHARES];
  uint8_t out[(BYTES_SEED_SE + CRYPTO_BYTES)*N_SHARES];
  uint8_t seedEP_masked[((2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t))*N_SHARES];

  int iter = 1000;
  uint64_t start, stop;

  start = cpucycles();
  for(int i=0; i < iter; ++i){
    masked_shake(out, BYTES_SEED_SE + CRYPTO_BYTES, in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);
    masked_shake((uint8_t *)seedEP_masked, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), G2in_masked, 1 + BYTES_SEED_SE);
  }
  stop = cpucycles();
  printf("\nBench_SHAKE Avg kcycles: %lu\n", (stop-start)/(1000*iter));
}

void bench_CT_SELECT(){

  uint16_t Bp[PARAMS_N*PARAMS_NBAR] = {0};                      
  ALIGN_HEADER(32) uint16_t masked_BBp[PARAMS_N*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};

  uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
  uint16_t masked_CC[PARAMS_NBAR*PARAMS_NBAR*N_SHARES] = {0};

  uint8_t masked_selector[N_SHARES];
  uint8_t masked_sk_s[CRYPTO_BYTES * N_SHARES];
  uint8_t kprime_masked[N_SHARES * CRYPTO_BYTES]; 
  uint8_t masked_Fin[(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES)*N_SHARES] = {0};
  const uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};

  int iter = 1000;
  uint64_t start, stop;

  start = cpucycles();
  for(int i=0; i < iter; ++i){
    masked_frodo_compare(masked_BBp, Bp, masked_CC, C, masked_selector);
    
  }
  stop = cpucycles();
  printf("\nBench_Compare Avg kcycles: %lu\n", (stop-start)/(1000*iter));

  start = cpucycles();
  for(int i=0; i < iter; ++i){
    masked_ct_select(masked_Fin, ct, kprime_masked, masked_sk_s, masked_selector);
    
  }
  stop = cpucycles();
  printf("Bench_select Avg kcycles: %lu\n", (stop-start)/(1000*iter));

  
}

void bench_SAMPLER(){

  ALIGN_HEADER(32) uint16_t masked_Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};  




  int iter = 1000;
  uint64_t start, stop;

  start = cpucycles();
  for(int i=0; i < iter; ++i){
    masked_frodo_sample_n(masked_Sp, PARAMS_N*PARAMS_NBAR);
    
  }
  stop = cpucycles();
  printf("\nBench_sample_n kcycles: %lu\n", (stop-start)/(1000*iter));



  
}

#endif





void mask_mat(uint16_t* masked_mat , uint16_t* mat, int size){
  arith_mask_value_u16_array(masked_mat, mat, size, N_SHARES);
}

void unmask_mat(uint16_t* mat, uint16_t* masked_mat, int size){
  int i;
  arith_unmask_value_u16_array(mat, masked_mat, size, N_SHARES);
  for(i = 0; i < size; ++i){
    mat[i] &= ((1<<PARAMS_LOGQ)-1);
  } 
}

void print_mat(uint16_t* mat, int size){
  int i;
  for(i=0; (i < 20) && (i < size); ++i)
    printf("%u ", mat[i]);
  printf("\n\n");
}

void print_masked_mat(uint16_t* masked_mat, int size){
  uint16_t mat[size];
  unmask_mat(mat, masked_mat, size);
  print_mat(mat, size);
}

void mask_uint8_t_array(uint8_t* masked_s, const uint8_t* s, int size){
  mask_bitstring(masked_s, s, size, N_SHARES);
}

void unmask_uint8_t_array(uint8_t* s, const uint8_t* masked_s, int size){
  unmask_bitstring(s, masked_s, size, N_SHARES);
}

void print_uint8_t_array(uint8_t* s, int size){
  print_masked_bitstring(s, size, 1);
}


void print_masked_uint8_t_array(uint8_t* s, int size){
  print_masked_bitstring(s, size, N_SHARES);
}


