#include <stdint.h>
#include "./basics.h"
#include "./utils.h"
#include "./random.h"
#include "./gadgets.h"

#ifndef FRODO_PARAMS
  #define FRODO_PARAMS 640
#endif

#if FRODO_PARAMS == 640

#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 2
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8

uint32_t L_CDF_TABLE[13] = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
uint32_t L_CDF_TABLE_LEN = 13;

#elif FRODO_PARAMS == 976

#define PARAMS_N 976
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 3
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT (2*CRYPTO_BYTES)
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES

uint16_t L_CDF_TABLE[11] = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
uint16_t L_CDF_TABLE_LEN = 11;


#elif FRODO_PARAMS == 1344

#define PARAMS_N 1344
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 4
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT (2*CRYPTO_BYTES)
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES

uint16_t L_CDF_TABLE[7] = {9142, 23462, 30338, 32361, 32725, 32765, 32767};
uint16_t L_CDF_TABLE_LEN = 7;

#else 
#error Wrong parameters.

#endif

// the compilation toolchain is driving me crazy
// #ifdef TEST_FRODO_GADGETS
// uint32_t CDF_TABLE[13] = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
// uint32_t CDF_TABLE_LEN = 13;
// #else
// extern uint32_t CDF_TABLE[13];
// extern uint32_t CDF_TABLE_LEN;
// #endif


//#endif


/*
int masked_compare(uint16_t* a, uint16_t* b, int n){
  // size of a (and b): (PARAMS_N*PARAMS_NBAR + PARAMS_NBAR*PARAMS_NBAR)*N 
  int i, j, size = PARAMS_N*PARAMS_NBAR + PARAMS_NBAR*PARAMS_NBAR;
  uint16_t acc[n], temp_arith[n], temp_bool[n], temp_ZT[n], temp_acc[n];
  int res = 0;

  acc[0] = 1;
  for(i = 1; i < n; ++i){
    acc[i] = 0;
  }
  for(i = 0; i < size; ++i){
    for(j = 0; j < n; ++j){
      a[i + j*size] -= b[i + j*size];
    }
  }

  for(i = 0; i < size; ++i){
    for(j = 0; j < n; ++j){
      temp_arith[j] = a[i + j*size]; 
    }
    convert_AB_u16(temp_bool, temp_arith, n);
    sec_zero_test_bool_u16(temp_ZT, temp_bool, n);
    sec_and_u16(temp_acc, temp_ZT, acc, n);
    for(j = 0; j < n; ++j){
      acc[j] = temp_acc[j];  
    }
  }

  for(j = 0; j < n; ++j){
    res ^= acc[j];
  }
  return res;

}*/



/****************************************************************************************************************************************
*  Check whether B'||C is equal to B''||C' in decapsulation and write the result in masked_selector
*  Inputs: 
*    - "masked_BBp": 1st component B'' of the masked recomputed ciphertext (Arith)      | uint16_t[N_SHARES*PARAMS_N*PARAMS_NBAR] 
*    - "Bp": (unpacked) 1st component B' of the ciphertext received as input of decaps  | uint16_t[PARAMS_N*PARAMS_NBAR] 
*    - "masked_CC": 2nd component C' of the masked recomputed ciphertext  (Arith)       | uint16_t[N_SHARES*PARAMS_NBAR*PARAMS_NBAR]
*    - "C": (unpacked) 2nd component C of the ciphertext received as input of decaps    | uint16_t[PARAMS_NBAR*PARAMS_NBAR]
*    - "masked_selector": will contain the masked result of the comparison (Bool)       | uint8_t[N_SHARES]
*    - "n" number of shares, set to N_SHARES when called by FrodoKem                    | int
*****************************************************************************************************************************************/    
void masked_compare(uint16_t* masked_BBp, uint16_t* Bp, uint16_t* masked_CC, uint16_t* C, uint8_t* masked_selector, int n){

 
  int i, j, size_Bp = PARAMS_N*PARAMS_NBAR, size_C = PARAMS_NBAR*PARAMS_NBAR;
  uint16_t acc[n], temp_arith[n], temp_bool[n], temp_ZT[n], temp_acc[n];

  acc[0] = 0xFFFF;
  for(i = 1; i < n; ++i){
    acc[i] = 0;
  }

  for(i = 0; i < size_Bp; ++i){
    masked_BBp[i] = (masked_BBp[i] - Bp[i]);

  }

  for(i = 0; i < size_C; ++i){
    masked_CC[i] = (masked_CC[i] - C[i]);
  }


  for(i = 0; i < size_Bp; ++i){
    for(j = 0; j < n; ++j){
      temp_arith[j] = masked_BBp[i + j*size_Bp] ; 
    }
    convert_AB_u16(temp_bool, temp_arith, n);
    for(j = 0; j < n; ++j){
      temp_bool[j] &= ((1<<PARAMS_LOGQ)-1);
    }
    temp_bool[0] = ~temp_bool[0]; 
    sec_and_u16(temp_acc, temp_bool, acc, n);
    for(j = 0; j < n; ++j){
      acc[j] = temp_acc[j];  
    }
  }


  for(i = 0; i < size_C; ++i){
    for(j = 0; j < n; ++j){
      temp_arith[j] = masked_CC[i + j*size_C]; 
    }
    convert_AB_u16(temp_bool, temp_arith, n);
    for(j = 0; j < n; ++j){
      temp_bool[j] &= ((1<<PARAMS_LOGQ)-1);
    }
    temp_bool[0] = ~temp_bool[0]; 
    sec_and_u16(temp_acc, temp_bool, acc, n);
    for(j = 0; j < n; ++j){
      acc[j] = temp_acc[j];  
    }
  }

  temp_acc[0] = ~temp_acc[0];
  sec_zero_test_bool_u16(temp_ZT, temp_acc, n);

  // Acc is 1 if all 0

  for(j = 0; j < n; ++j){
    masked_selector[j] = -(temp_ZT[j]&0x1); //extend last bit to the whole variable
  }

  //Masked selector is 0 if all 0, 0xFF otherwise.
  masked_selector[0] = (~masked_selector[0]); 

}



/****************************************************************************************************************************************
* Decode a bit string encoded in a masked matrix of size PARAMS_NBAR*PARAMS_NBAR
* It extracts PARAMS_EXTRACTED_BITS per coefficient. The output is thus PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR/8 bytes long.
* Inputs:
*   - "out" Masked bit string, plaintext of the underlying PKE (Bool) | uint16_t[(BYTES_MU/2)*N_SHARES]
*   - "in"  Masked input matrix (Arith)                               | uint16_t[N_SHARES*PARAMS_NBAR*PARAMS_NBAR]
*   - "n" number of shares, set to N_SHARES when called by FrodoKem   | int
****************************************************************************************************************************************/

void masked_key_decode(uint16_t *out, const uint16_t *in, int n)
{ 
    unsigned int i, j, index = 0, npieces_word = 8;
    int k, in_size = PARAMS_NBAR * PARAMS_NBAR;
    unsigned int nwords = (PARAMS_NBAR * PARAMS_NBAR) / 8;
    uint16_t maskex=((uint16_t)1 << PARAMS_EXTRACTED_BITS) -1, maskq =((uint16_t)1 << PARAMS_LOGQ) -1;
    uint8_t  *pos = (uint8_t*)out;
    uint64_t templong[n];

    uint16_t temp[n], shifted_temp[n];

    for (i = 0; i < nwords; i++) {
        for(k = 0; k < n; k++) {
          templong[k] = 0;
        }

        for (j = 0; j < npieces_word; j++) {  // temp = floor(in*2^{-11}+0.5)
            
            temp[0] = ((in[index]) & maskq) + (1 << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1));
            for(k = 1; k < n; ++k) temp[k] = (in[k*in_size + index]) & maskq;

            convert_AB_u16(shifted_temp, temp, n);
            for(k = 0; k < n; k++){
              shifted_temp[k] = shifted_temp[k] >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
            }
            
            for(k = 0; k < n; k++) templong[k] |= ((uint64_t)(shifted_temp[k] & maskex)) << (PARAMS_EXTRACTED_BITS * j);
            index++;
        }

        for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
            for(k = 0; k < n; k++) pos[k*PARAMS_EXTRACTED_BITS*nwords + i*PARAMS_EXTRACTED_BITS + j] = (templong[k] >> (8*j)) & 0xFF;
    }
}


/*****************************************************************************************************************************************
* Encode a masked bit string in a masked matrix of size PARAMS_NBAR*PARAMS_NBAR
* It encodes PARAMS_EXTRACTED_BITS per coefficient.
* Inputs:
*   - "out"  Masked out matrix (Arith)                                | uint16_t[N_SHARES*PARAMS_NBAR*PARAMS_NBAR]
*   - "in" Masked bit string, plaintext of the underlying PKE (Bool)  | uint16_t[(BYTES_MU/2)*N_SHARES]
*   - "n" number of shares, set to N_SHARES when called by FrodoKem   | int
*****************************************************************************************************************************************/
void masked_key_encode(uint16_t *out, const uint16_t *in, int n) 
{ 
    unsigned int i, j, npieces_word = 8;
    int k, out_size = PARAMS_NBAR * PARAMS_NBAR;
    unsigned int nwords = (PARAMS_NBAR*PARAMS_NBAR)/8;
    uint64_t temp[n], mask = ((uint64_t)1 << PARAMS_EXTRACTED_BITS) - 1;
    uint16_t* pos = out;
    uint16_t bool_masked_coef[n], arith_masked_coef[n];

    for (i = 0; i < nwords; i++) {
        for(k = 0; k < n; ++k){
          temp[k] = 0;
        }
        for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
          for(k = 0; k < n; ++k){
            temp[k] |= ((uint64_t)((uint8_t*)in)[k*PARAMS_EXTRACTED_BITS*nwords + i*PARAMS_EXTRACTED_BITS + j]) << (8*j);
          }
        for (j = 0; j < npieces_word; j++) { 

            for(k = 0; k < n; ++k){
              bool_masked_coef[k] = (uint16_t)((temp[k] & mask) << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS));  
            }

            convert_BA_u16(arith_masked_coef, bool_masked_coef, n);

            for(k = 0; k < n; ++k){
              *(pos + k*out_size) = arith_masked_coef[k];
              temp[k] >>= PARAMS_EXTRACTED_BITS;
            }
            
            pos++;
        }
    }
}


void masked_sample_n(uint16_t *s, const size_t len, unsigned int n) 
{
    unsigned int i, j, k;
    uint16_t delta[n];
    uint16_t b[n], b_p[n];

    for (i = 0; i < len; ++i) {
        uint16_t x[n];
        uint16_t prnd[n];
        uint16_t sign[n];
        uint16_t T[n];

        for (j = 0; j < n; j++)
        {
            sign[j] = s[i + j*len] & 1;
            prnd[j] = s[i + j*len] >> 1;
            x[j] = 0;
            T[j] = 0;
        }

        for (j = 0; j < (unsigned int)(L_CDF_TABLE_LEN); j++) {
            T[0] = (uint16_t)-L_CDF_TABLE[j]-1;
            
            sec_add_u16(delta, prnd, T, n);

            for(k=0; k < n; ++k) {
                b[k] = ((int16_t)delta[k] >> 15);
                b_p[k] = b[k];
            }

            b[0] = ~b[0];
            T[0] = j+1;

            sec_and_u16(delta, T, b, n);
            sec_and_u16(b, x, b_p, n);

            for(k=0; k < n; ++k) {
                x[k] = delta[k] ^ b[k];
            }

            linear_bool_refresh_u16(x, n);
        }

        for (j = 0; j < n; j++) {
            x[j] ^= (uint16_t)-sign[j];
        }
        sec_add_u16(x, sign, x, n);

        convert_BA_u16(b, x, n);
        for (j = 0; j < n; j++) {
            s[i + j*len] = b[j];
        }
    }
}






#ifdef TEST_FRODO_GADGETS

#if defined(PQM4)
    #include "hal.h"
    #include "sendfn.h"

static int printf(const char *format, ...)
{
    hal_send_str(format);
    return 1;
}

#else
    #include <stdio.h>
#endif

static void frodo_key_decode(uint16_t *out, const uint16_t *in)
{ // Decoding
    unsigned int i, j, index = 0, npieces_word = 8;
    unsigned int nwords = (PARAMS_NBAR * PARAMS_NBAR) / 8;
    uint16_t temp, maskex=((uint16_t)1 << PARAMS_EXTRACTED_BITS) -1, maskq =((uint16_t)1 << PARAMS_LOGQ) -1;
    uint8_t  *pos = (uint8_t*)out;
    uint64_t templong;

    for (i = 0; i < nwords; i++) {
        templong = 0;
        for (j = 0; j < npieces_word; j++) {  // temp = floor(in*2^{-11}+0.5)
            temp = ((in[index] & maskq) + (1 << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1))) >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
            templong |= ((uint64_t)(temp & maskex)) << (PARAMS_EXTRACTED_BITS * j);
            index++;
        }
        for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
            pos[i*PARAMS_EXTRACTED_BITS + j] = (templong >> (8*j)) & 0xFF;
        }
}


static void frodo_key_encode(uint16_t *out, const uint16_t *in) 
{ // Encoding
    unsigned int i, j, npieces_word = 8;
    unsigned int nwords = (PARAMS_NBAR*PARAMS_NBAR)/8;
    uint64_t temp, mask = ((uint64_t)1 << PARAMS_EXTRACTED_BITS) - 1;
    uint16_t* pos = out;

    for (i = 0; i < nwords; i++) {
        temp = 0;
        for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
            temp |= ((uint64_t)((uint8_t*)in)[i*PARAMS_EXTRACTED_BITS + j]) << (8*j);
        for (j = 0; j < npieces_word; j++) { 
            *pos = (uint16_t)((temp & mask) << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS));  
            temp >>= PARAMS_EXTRACTED_BITS;
            pos++;
        }
    }
}

static void frodo_sample_n(uint16_t *s, const size_t n) 
{
    unsigned int i, j;

    for (i = 0; i < n; ++i) {
        uint16_t sample = 0;
        uint16_t prnd = s[i] >> 1;
        uint16_t sign = s[i] & 0x1;

        for (j = 0; j < (unsigned int)(L_CDF_TABLE_LEN - 1); j++) {
            sample += (uint16_t)(L_CDF_TABLE[j] - prnd) >> 15;
        }
        s[i] = ((-sign) ^ sample) + sign;
    }
}




void test_key_decode(){
  int ITER = 50;
  int max_n = 4;

  uint16_t W[PARAMS_NBAR*PARAMS_NBAR]; 
  uint16_t masked_W[PARAMS_NBAR*PARAMS_NBAR*max_n]; 
  uint16_t temp[max_n];

  uint8_t muprime[BYTES_MU]; 
  uint8_t masked_muprime[BYTES_MU*max_n]; 
  uint8_t unmasked_muprime[BYTES_MU];


  for(int it = 0; it < ITER; ++it){

    for(int n=2; n <= max_n; ++n){

      for(int i=0; i < PARAMS_NBAR*PARAMS_NBAR; i++) {
        W[i] = rand_u16();
        arith_mask_value_u16(temp, W[i], n);
        for(int k=0; k < n; ++k) masked_W[k*PARAMS_NBAR*PARAMS_NBAR+i] = temp[k];

      }

      frodo_key_decode((uint16_t*)muprime, W);
      masked_key_decode((uint16_t*)masked_muprime, masked_W, n);
      unmask_bitstring(unmasked_muprime, masked_muprime, BYTES_MU, n);

      //print_masked_bitstring(muprime, BYTES_MU, 1);
      //print_masked_bitstring(masked_muprime, BYTES_MU, n);


      for(int i=0; i < BYTES_MU; ++i){
        if (muprime[i] != unmasked_muprime[i]){
          printf("Test key decode fail\n");
          return;
        }
      }
    }
  }
  printf("Test key decode success\n");




}


static void test_key_encode(){
  
  int ITER = 50;
  int max_n = 4;
  
  uint8_t in[BYTES_MU];
  uint8_t masked_in[BYTES_MU*max_n];

  uint16_t CC[PARAMS_NBAR*PARAMS_NBAR];
  uint16_t masked_CC[PARAMS_NBAR*PARAMS_NBAR*max_n];
  uint16_t unmasked_CC[PARAMS_NBAR*PARAMS_NBAR];

  uint16_t temp[max_n];

  for(int it = 0; it < ITER; ++it){ 
    for(int n = 2; n <= max_n; ++n){

      for(int i=0; i < BYTES_MU; i++) {
        in[i] = rand_u16();
        bool_mask_value_u16(temp, in[i], n);
        for(int k=0; k < n; ++k) masked_in[k*BYTES_MU+i] = temp[k];

      }


      //print_masked_bitstring(in, BYTES_MU, 1);
      //print_masked_bitstring(masked_in, BYTES_MU, n);

      frodo_key_encode(CC, (uint16_t*)in);
      masked_key_encode(masked_CC, (uint16_t*)masked_in, n);

  /*
    #if !defined(PQM4)
      for(int i=0; i < PARAMS_NBAR*PARAMS_NBAR; ++ i){
        printf("%u ", CC[i]);
      }
      printf("\n");
    #endif
  */

      for(int i=0; i < PARAMS_NBAR*PARAMS_NBAR; ++i){
        for(int k=0; k < n; ++k){
          temp[k] = masked_CC[k*PARAMS_NBAR*PARAMS_NBAR + i];
        }
    #if !defined(PQM4)
        //printf("%u ", arith_unmask_value_u16(temp, n));
    #endif
        unmasked_CC[i] = arith_unmask_value_u16(temp, n);
      }
      //printf("\n");
      for(int i=0; i < PARAMS_NBAR*PARAMS_NBAR; ++i){
        if (CC[i] != unmasked_CC[i]){
    #if defined(PQM4)
          send_unsigned("n:", n);
    #endif
          printf("Test key encode fail\n");
          return;
        }
      }
    }
  }

  printf("Test key encode success\n");


}


static void test_masked_compare(){

  int ITER = 5;
  int max_n = 4;
  int i, j;
  int size_Bp = PARAMS_N*PARAMS_NBAR;
  int size_C = PARAMS_NBAR*PARAMS_NBAR;
  uint16_t masked_BBp[size_Bp*max_n], masked_CC[size_C*max_n], Bp[size_Bp], C[size_C], temp[max_n], val;
  uint8_t masked_selector[max_n];
  uint8_t unmasked_selector;
  uint8_t coin_flip;


  for(int it = 0; it <= ITER; ++it){
    for(int n = 2; n < max_n; ++n){
      for(i = 0; i < size_Bp; ++i){
        val = rand_u16();
        arith_mask_value_u16(temp, val, n);
        for(j = 0; j < n; ++j){
          masked_BBp[i + size_Bp*j] = temp[j];
        }
        Bp[i] = val;
      }

      for(i = 0; i < size_C; ++i){
        val = rand_u16();
        arith_mask_value_u16(temp, val, n);
        for(j = 0; j < n; ++j){
          masked_CC[i + size_C*j] = temp[j];
        }
        C[i] = val;
      }

      coin_flip = rand_u16()&1;
      
      if (coin_flip == 1){
        coin_flip = rand_u16()&1;
        Bp[rand_u16()%size_Bp] += coin_flip;
      }
      else{
        coin_flip = rand_u16()&1;
        C[rand_u16()%size_Bp] += coin_flip;
      }
      
      masked_compare(masked_BBp, Bp, masked_CC, C, masked_selector, n);
      //print_masked_bitstring(masked_selector, 1, n);

      unmask_bitstring(&unmasked_selector, masked_selector, 1, n);

      if (((coin_flip == 0) && (unmasked_selector != 0x00)) || ((coin_flip == 1) && (unmasked_selector != 0xFF))){
        printf("Test compare fail\n");
        return;
      }
    }
  }

  printf("Test compare success\n");


}

static void test_sampler()
{
    size_t len = 4;
    unsigned int n = 2;
    unsigned int i, j, k;
    uint16_t s[len], s_unmasked[len];
    uint16_t s_masked[n*len];
    
    for (i = 0; i < 2*PARAMS_Q; i++)
    {
        for (k = 0; k < len; k++)
        {
            s[k] = i;
            s_masked[k] = i;
            for (j = 1; j < n; j++)
            {
                s_masked[k + j*len] = rand_u16();
                s_masked[k] ^= s_masked[k+j*len];
            }
        }
        
        frodo_sample_n(s, len);
        masked_sample_n(s_masked, len, n);

        for (k = 0; k < len; k++) {
            s_unmasked[k] = s_masked[k];
            for (j = 1; j < n; j++) {
                s_unmasked[k] = (s_unmasked[k] + s_masked[k+j*len]) % (1 << (PARAMS_LOGQ + 1));
            }

            if (s_unmasked[k] != s[k])
            {
            #if defined(PQM4)
                send_unsigned("error:", i);
                send_unsigned("s_unmasked =", s_unmasked[k]);
                send_unsigned("s =", s[k]);
            #else
                printf("error: %d\n", i);
                printf("s_unmasked = %u\n", s_unmasked[k]);
                printf("s = %u\n", s[k]);
            #endif
                return;
            }
        }   
    }
    if (i == 2*PARAMS_Q) {
      printf("Sampler: Success\n");
    }
}

int main(){
  printf("Frodo gadgets Hello world\n");
#if defined(PQM4)
  send_unsigned("PARAMS_N =", (uint8_t)PARAMS_N);
  send_unsigned("PARAMS_NBAR =", (uint8_t)PARAMS_NBAR);
  send_unsigned("PARAMS_LOGQ =", (uint8_t)PARAMS_LOGQ);
#else
  printf("Frodo parameters: N = %i | NBAR = %i | LogQ = %i\n", PARAMS_N, PARAMS_NBAR,  PARAMS_LOGQ);
#endif
  init_rng();
  test_key_decode();
  test_key_encode();
  test_masked_compare();
  test_sampler();
}

#endif