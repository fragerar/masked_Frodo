#if defined(PQM4)
    #include "hal.h"
    #include "sendfn.h"
#else
    #include <stdio.h>
#endif
#include <stdint.h>
#include <stddef.h>

#include "gadgets.h"
#include "basics.h"
#include "random.h"
#include "utils.h"



#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 2
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8


#ifndef PQM4
#define ITERATIONS_SMALL 100000
#define ITERATIONS_BIG 1000
#else
#define ITERATIONS_SMALL 1
#define ITERATIONS_BIG 1
#endif

int64_t cpucycles(void)
{ 

#ifndef PQM4
  unsigned int hi, lo;

  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);
#else
  return hal_get_time();
#endif
}



static int println(const char *format, ...)
{
#if defined(PQM4)
  hal_send_str(format);
#else
  printf(format);
  printf("\n");
#endif
  return 1;
}



//basics


int64_t bench_sec_and(int n){
  int64_t start, stop;

  uint16_t a[n], b[n], c[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    sec_and_u16(c, b, a, n);
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}

int64_t bench_sec_mul(int n){
  int64_t start, stop;

  uint16_t a[n], b[n], c[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    sec_mul_u16(c, b, a, n);
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}

int64_t bench_sec_add(int n){
  int64_t start, stop;

  uint16_t a[n], b[n], c[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    sec_add_u16(c, b, a, n);
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}

int64_t conv_BA(int n){
  int64_t start, stop;

  uint16_t a[n], b[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    convert_BA_u16(b, a, n);
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}

int64_t conv_AB(int n){
  int64_t start, stop;

  uint16_t a[n], b[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    convert_AB_u16(b, a, n); 
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}


int64_t bench_sec_ZT(int n){
  int64_t start, stop;

  uint16_t a[n], b[n];

  start = cpucycles();
  for(int i=0; i < ITERATIONS_SMALL; i++){
    sec_zero_test_bool_u16(b, a, n);
  }
  stop = cpucycles();
  return (stop-start)/ITERATIONS_SMALL;
}



int64_t bench_key_encode(int n){

  int i;
  uint8_t masked_in[BYTES_MU*n];
  uint16_t masked_CC[PARAMS_NBAR*PARAMS_NBAR*n];

  uint16_t temp[n];

  int64_t start, stop;

  for(i=0; i < BYTES_MU; i++) {
    bool_mask_value_u16(temp, rand_u16(), n);
    for(int k=0; k < n; ++k) masked_in[k*BYTES_MU+i] = temp[k];

  }

  start = cpucycles();
  for(i=0; i < ITERATIONS_BIG; i++){
    masked_key_encode(masked_CC, (uint16_t*)masked_in, n);
  }
  stop = cpucycles();

  return (stop-start)/ITERATIONS_BIG;

}


int64_t bench_key_decode(int n){

  int i;

  uint8_t masked_muprime[BYTES_MU*n]; 
  uint16_t masked_W[PARAMS_NBAR*PARAMS_NBAR*n]; 
  uint16_t temp[n];

  int64_t start, stop;


  for(int i=0; i < PARAMS_NBAR*PARAMS_NBAR; i++) {
    arith_mask_value_u16(temp, rand_u16(), n);
    for(int k=0; k < n; ++k) masked_W[k*PARAMS_NBAR*PARAMS_NBAR+i] = temp[k];

  }

  start = cpucycles();
  for(i=0; i < ITERATIONS_BIG; i++){
    masked_key_decode((uint16_t*)masked_muprime, masked_W, n);
  }
  stop = cpucycles();

  return (stop-start)/ITERATIONS_BIG;

}


int64_t bench_compare(int n){
  int i;
  uint16_t masked_BBp[PARAMS_N*PARAMS_NBAR*n], Bp[PARAMS_N*PARAMS_NBAR], masked_CC[PARAMS_NBAR*PARAMS_NBAR*n], C[PARAMS_NBAR*PARAMS_NBAR];
  uint8_t masked_selector[n];
  int64_t start, stop;

  start = cpucycles();
  for(i=0; i < ITERATIONS_BIG; i++){
    masked_compare(masked_BBp, Bp, masked_CC, C, masked_selector, n);
  }
  stop = cpucycles();

  return (stop-start)/ITERATIONS_BIG;
}

int64_t bench_sampler(int n){
  int i;
  uint16_t s[PARAMS_N*PARAMS_NBAR*n];
  int64_t start, stop;

  start = cpucycles();
  for(i=0; i < ITERATIONS_BIG; i++){
    masked_sample_n(s, PARAMS_N*PARAMS_NBAR, n);
  }
  stop = cpucycles();

  return (stop-start)/ITERATIONS_BIG;
}


void print_llu(const char *s, uint64_t x){
  #if defined(PQM4)
    send_unsignedll((s), (x));
  #else
    printf(s);
    printf("%li\n", x);
  #endif

}




int main(){
  println("Benchmarking...");
  int n_shares;

  int MIN_SHARES = 2, MAX_SHARES = 8;
  int SCALING = 1000; // kilocycles

  #if defined(PQM4)
    MAX_SHARES = 3;

  #if defined(ASM)
    println("Cortex-M4 ASM on");
  #else
    println("Cortex-M4 ASM off");
  #endif
  #endif


  printf("Sec_and & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_sec_and(n_shares));
  }
  printf("%ld\n",bench_sec_and(MAX_SHARES));
  //println("=========================");

  /*println("Sec_mul: ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES+1; n_shares++){
     print_llu("",bench_sec_mul(n_shares));
  }
  println("=========================");*/

  printf("Sec_add & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_sec_add(n_shares));
  }

  printf("%ld\n",bench_sec_add(MAX_SHARES));
  //println("=========================");


  printf("conv_BA & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",conv_BA(n_shares));
  }
  printf("%ld\n",conv_BA(n_shares));
  //println("=========================");

  printf("conv_AB & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
      printf("%ld & ",conv_AB(n_shares));
  }
  printf("%ld\n",conv_AB(n_shares));
  //println("=========================");

  printf("Sec_ZT & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_sec_ZT(n_shares));
  }
  printf("%ld\n ",bench_sec_ZT(n_shares));
  


  println("=========================");




  print_llu("Scaling = ",SCALING);


  printf("Key encode & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_key_encode(n_shares)/SCALING);
  }
  printf("%ld\n", bench_key_encode(MAX_SHARES)/SCALING);
  //println("=========================");

  printf("Key decode & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_key_decode(n_shares)/SCALING);
  }
  printf("%ld\n", bench_key_decode(MAX_SHARES)/SCALING);
  //println("=========================");



  print_llu("Scaling = ",SCALING);

  printf("Compare & ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_compare(n_shares)/SCALING);
  }
  printf("%ld\n",bench_compare(MAX_SHARES)/SCALING);
  //println("=========================");

  println("Sampler: ");
  for(n_shares=MIN_SHARES; n_shares < MAX_SHARES; n_shares++){
     printf("%ld & ",bench_sampler(n_shares)/SCALING);
  }
  printf("%ld\n", bench_sampler(MAX_SHARES)/SCALING);
  println("=========================");


  return -1;
}