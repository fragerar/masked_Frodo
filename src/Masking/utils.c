#include "utils.h"
#include "random.h"

#include <stdio.h>

void linear_arith_refresh_u16(uint16_t* x, int n){

  int i;
  uint16_t nonce;

  for(i = 0; i < n-1; ++i){
    nonce = rand_u16();
    x[  i] += nonce;
    x[n-1] -= nonce;
  }

}

void full_arith_refresh_u16(uint16_t* x, int n){

  int i, j;
  uint16_t nonce;

  for(i = 0; i < n; i++){
    for(j = i+1; j < n; j++){
      nonce = rand_u16();
      x[i] += nonce;
      x[j] -= nonce;
    }
  }
}

void linear_bool_refresh_u16(uint16_t* x, int n){

  int i;
  uint16_t nonce;
  for(i = 0; i < n-1; ++i){
    nonce = rand_u16();
    x[  i] ^= nonce;
    x[n-1] ^= nonce;
  }
}

void full_bool_refresh_u16(uint16_t* x, int n){

  int i, j;
  uint16_t nonce;

  for(i = 0; i < n; i++){
    for(j = i+1; j < n; j++){
      nonce = rand_u16();
      x[i] ^= nonce;
      x[j] ^= nonce;
    }
  }
}


void arith_mask_value_u16(uint16_t* y, uint16_t x, int n){

  int i;
  y[0] = x;
  for(i = 1; i < n; ++i){
    y[i] = 0;
  }
  linear_arith_refresh_u16(y, n);

}

void arith_mask_value_u16_array(uint16_t* y, uint16_t* x, int size, int n){

  int i, j;
  uint16_t temp[n], val;

  for(i=0; i < size; ++i){
    val = x[i];
    arith_mask_value_u16(temp, val, n);
    for(j=0; j < n; ++j){
      y[i+size*j] = temp[j];
    }
  }
}


void bool_mask_value_u16(uint16_t* y, uint16_t x, int n){

  int i;
  y[0] = x;
  for(i = 1; i < n; ++i){
    y[i] = 0;
  }
  linear_bool_refresh_u16(y, n);

}

uint16_t arith_unmask_value_u16(const uint16_t* y, int n){

  uint16_t acc = 0;
  int i;
  for(i = 0; i < n; ++i){
    acc += y[i];
  }
  return acc;
}



void arith_unmask_value_u16_array(uint16_t* y, const uint16_t* x, int size, int n){
  int i, j;

  for(i=0; i < size; i++){
    y[i] = x[i];
    for(j=1; j < n; j++){
      y[i] += x[i + size*j];
    }
  }
}


uint16_t bool_unmask_value_u16(const uint16_t* y, int n){
 
 uint16_t acc = 0;
  int i;
  for(i = 0; i < n; ++i){
    acc ^= y[i];
  }
  return acc;
}


uint64_t bool_unmask_value_u64(const uint64_t* y, int n){
 
 uint64_t acc = 0;
  int i;
  for(i = 0; i < n; ++i){
    acc ^= y[i];
  }
  return acc;
}


void mask_bitstring(uint8_t* masked_s, const uint8_t* s, int size, int n){

  uint8_t temp;
  int i, j;
  for(i = 0; i < size; ++i){
    masked_s[i] = s[i];
  }

  for(i = 0; i < size; ++i){
    for(j = 1; j < n; ++j){
      temp = (uint8_t)(rand_u16()&0xFF);
      masked_s[j*size + i] = temp;
      masked_s[i] ^= temp;
    }
  }
}


void unmask_bitstring(uint8_t* unmasked_s, const uint8_t* masked_s, int size, int n){
  // Total size masked_s = size*n.
  //j-th unmasked char is s[j] ^ s[size+j] ^ s[2*size+j] ^ ... ^ s[(n-1)*size+j]

  int i, j;
  for(i = 0; i < size; ++i){
    unmasked_s[i] = masked_s[i];
  }

  for(i = 0; i < size; ++i){
    for(j = 1; j < n; ++j){
      unmasked_s[i] ^= masked_s[j*size + i];
    }
  }
}

void print_arith_masked_u16(const uint16_t* x, int n){

  int i;
  for(i = 0; i < n; ++i){
    printf("%u ", x[i]);
  }
  printf("= %u\n", arith_unmask_value_u16(x, n));

}

void print_bool_masked_u16(const uint16_t* x, int n){

  int i;
  for(i = 0; i < n; ++i){
    printf("%04X ", x[i]);
  }
  printf("= %04X\n", bool_unmask_value_u16(x, n));

}


void print_bool_masked_u64(const uint64_t* x, int n){

  int i;
  for(i = 0; i < n; ++i){
    printf("%llX ", x[i]);
  }
  printf("= %llX\n", bool_unmask_value_u64(x, n));

}


void print_masked_bitstring(const uint8_t* s, int size, int n){
  int i;
  uint8_t unmasked_s[size];

  unmask_bitstring(unmasked_s, s, size, n);

  for(i = 0; (i < size) ; ++i){
    printf("%02X", unmasked_s[i]);
  }
  printf("\n");
  

}

void print_arith_masked_u16_array(const uint16_t* x, int size, int n){
  uint16_t y[size];
  int i;
  arith_unmask_value_u16_array(y, x, size, n);
  
  for(i=0; (i < 20000) && (i < size); i++){
    printf("%u ", y[i]);
  }
  printf("\n");

}




#ifdef TESTS_UTILS



int main(){
  init_rng();

  int n = 5;
  int x = 12;
  uint16_t y1[n], y2[n];


  arith_mask_value_u16(y1, x, n);
  bool_mask_value_u16(y2, x, n);

  print_arith_masked_u16(y1, n);
  print_bool_masked_u16(y2, n);

  full_arith_refresh_u16(y1,n);
  full_bool_refresh_u16(y2,n);

  print_arith_masked_u16(y1, n);
  print_bool_masked_u16(y2, n);

}


#endif

