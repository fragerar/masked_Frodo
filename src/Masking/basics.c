#include "basics.h"
#include "random.h"
#include "utils.h"

static void expand(uint16_t *xp, uint16_t *x, int n2, int n){
  int i;
  uint16_t r;

  for(i = 0; i < n/2; i++){
    r = rand_u16();
    xp[2*i  ] = x[i]^r;
    xp[2*i+1] = r;
  }

  if ((n&1) == 1) {
    if (n2 == n/2){
      xp[n-1] = 0;
    } else {
      xp[n-1] = x[n2-1];
    }
  }
}



void order1_convert_AB_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool){


    uint16_t O, T;
    uint16_t G = pool[0];
    T = 2*G;
    y[0] = G^x[1];
    O = G&y[0];
    y[0] = T^x[0];
    G = G^y[0];
    G = G&x[1];
    O = O^G;
    G = T&x[0];
    O = O^G;
    
    for(int k=1; k <= 15; ++k){
      G = T & x[1];
      G = G ^ O;
      T = T & x[0];
      G = G ^ T;
      T = 2*G;
    }

    y[0] = y[0]^T;
    y[1] = x[1];
}

void order1_convert_BA_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool){
      uint16_t T, G;
      G = pool[0];
      T = x[0]^G;
      T = T-G;
      T = T^x[0];
      G = G^x[1];
      y[0] = x[0]^G;
      y[0] = y[0]-G;
      y[0] = y[0]^T;
      y[1] = x[1];
}

void order1_sec_and_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t* pool){
    z[0] = x[0] & y[0];
    z[1] = x[1] & y[1];
    
    uint16_t r = pool[0];
    uint16_t tmp = r ^ (x[0] & y[1]);
    tmp ^= (x[1] & y[0]);
    z[0] ^= r;
    z[1] ^= tmp;

}
void order1_sec_add_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t *pool){
    uint16_t arith_x[2], arith_y[2], arith_z[2];

    order1_convert_BA_u16(arith_x, x, pool+0);
    order1_convert_BA_u16(arith_y, y, pool+1);
    arith_z[0] = arith_x[0] + arith_y[0];
    arith_z[1] = arith_x[1] + arith_y[1];
    order1_convert_AB_u16(z, arith_z, pool+2);



}
void order1_sec_zero_test_bool_u16(uint16_t* out, uint16_t* in, const uint16_t *pool){

    const int k=16, logk=4;
    int i, j, n=2, rand_i=0;

    uint16_t z[n], temp[n];

    out[0] = (~in[0]) | ((1<<(1<<logk))-(1<<k));
    for(i=1; i < n; ++i) out[i] = in[i];

    for(i=0; i < logk; ++i){
      for(j=0; j < n; ++j) {
        z[j] = out[j] >> (1 << i);
      }
      z[0] ^= pool[rand_i];
      z[1] ^= pool[rand_i];
      rand_i++;
      order1_sec_and_u16(temp, z, out, pool+rand_i);
      rand_i++;
      for(j=0; j < n; ++j){
        out[j] = temp[j]; 
      }
    }
    for(i=0; i < n; ++i) out[i] = (out[i])&1;

    out[0] ^= pool[rand_i];
    out[1] ^= pool[rand_i];

}





void convert_AB_u16(uint16_t* y, const uint16_t* x, int n){
  if (n == 2){

//http://www.goubin.fr/papers/arith-final.pdf

    #define RAND_CONV_AB 1 // really ??
    uint16_t pool[RAND_CONV_AB];
    (void)n; 

    for (int i = 0; i < RAND_CONV_AB; i ++) {
      pool[i] = rand_u16();
    }
    #undef RAND_CONV_AB
#if defined(PQM4) && defined (ASM)
    asm_convert_AB_u16(y, x, pool);
#else
    order1_convert_AB_u16(y, x, pool);
#endif


  } else {

    // [CGV14] http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf Algo 4

    if( n == 1){
      y[0] = x[0];
      return;
    }


    uint16_t t[n/2];
    uint16_t tp[n], up[n];;
    uint16_t u[(n+1)/2];



    convert_AB_u16(t, x, n/2);

    expand(tp, t, n/2, n);
    
    convert_AB_u16(u, x+n/2, (n+1)/2);

    expand(up, u, (n+1)/2, n);

    sec_add_u16(y, tp, up, n);
  }

}



void convert_BA_u16(uint16_t* y, const uint16_t* x, int n){

    if (n == 2){



//http://www.goubin.fr/papers/arith-final.pdf

    #define RAND_CONV_BA 1 // really ??
    uint16_t pool[RAND_CONV_BA];
    (void)n; 

    for (int i = 0; i < RAND_CONV_BA; i ++) {
      pool[i] = rand_u16();
    }
    #undef RAND_CONV_BA
#if defined(PQM4) && defined (ASM)
    asm_convert_BA_u16(y, x, pool);
#else
    order1_convert_BA_u16(y, x, pool);
#endif

    }
    else{

      // [CGV14] http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf Algo 6

      uint16_t i;
      uint16_t ap[n], b[n], c[n];

      for(i = 0; i < n-1; i++){
        y[i] = rand_u16();
      }

      for(i = 0; i < n-1; i++){
        ap[i] = -y[i];
      }
      ap[n-1] = 0;

      convert_AB_u16(b, ap, n);
      sec_add_u16(c, x, b, n);

      for(i = 0; i<n; i++){
        linear_bool_refresh_u16(c,n);
      }

      y[n-1] = bool_unmask_value_u16(c,n);
    }


}



void sec_and_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n){

  // ISW https://people.eecs.berkeley.edu/~daw/papers/privcirc-crypto03.pdf 
  
  if (n == 2){


    uint16_t pool;
    (void)n; 

    pool = rand_u16();
#if defined(PQM4) && defined (ASM)    
    asm_sec_and_u16(z, x, y, &pool);

#else
    order1_sec_and_u16(z, x, y, &pool);
#endif



  } else {
    int i, j;
    uint16_t tmp, r;

    for(i = 0; i < n; i++){
      z[i] = x[i] & y[i];
    }

    for(i = 0; i < n; i++){
      for(j = i+1; j < n; j++){
        r = rand_u16(); 
        tmp = (r ^ (x[i]&y[j])) ^ (x[j]&y[i]);
        z[i] ^= r;
        z[j] ^= tmp;
      }
    }
  }
}



void sec_and_u8(uint8_t* z, const uint8_t* x, const uint8_t* y, int n){



  // ISW https://people.eecs.berkeley.edu/~daw/papers/privcirc-crypto03.pdf 


  if (n == 2){
#if defined(PQM4) && defined (ASM) && 0
    #define RAND_SEC_AND 1 
    uint8_t pool[RAND_SEC_AND];
    (void)n; 

    for (int i = 0; i < RAND_SEC_AND; i ++) {
      pool[i] = (uint8_t)rand_u16()&0xFF;
    }
    asm_sec_and_u8(z, x, y, pool);
    #undef RAND_SEC_ZERO_TEST


#else

    z[0] = x[0] & y[0];
    z[1] = x[1] & y[1];
    
    uint8_t r = rand_u16()&0xFF;
    uint8_t tmp = r ^ (x[0] & y[1]);
    tmp ^= (x[1] & y[0]);
    z[0] ^= r;
    z[1] ^= tmp;
#endif

  } else {
    int i, j;
    uint8_t tmp, r;

    for(i = 0; i < n; i++){
      z[i] = x[i] & y[i];
    }

    for(i = 0; i < n; i++){
      for(j = i+1; j < n; j++){
        r = rand_u16(); 
        tmp = (r ^ (x[i]&y[j])) ^ (x[j]&y[i]);
        z[i] ^= r;
        z[j] ^= tmp;
      }
    }
  }
}



void sec_add_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n){



  if (n == 2){



  #define RAND_SEC_ADD 3
    uint16_t pool[RAND_SEC_ADD];
    (void)n; 

    for (int i = 0; i < RAND_SEC_ADD; i ++) {
      pool[i] = rand_u16();
    }
  #undef RAND_SEC_ADD

#if defined(PQM4) && defined (ASM)
    asm_sec_add_u16(z, x, y, pool);
#else
    order1_sec_add_u16(z, x, y, pool);
#endif

  } else {
    // http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf Algo 3
    const int k = 16;
    int i, j;
    uint16_t a[n], u[n], w[n], ua[n];
    for(i = 0; i < n; i++){
      u[i] = 0;
    }

    sec_and_u16(w, x, y, n);

    for(i = 0; i < n; i++){
      a[i] = x[i]^y[i];
    }

    for(i = 0; i < k-1; i++){
      sec_and_u16(ua, a, u, n);
      for(j = 0; j < n; j++) {
        u[j]=(2*(ua[j] ^ w[j]));
      }
    }

    for(i=0; i < n; i++){
      z[i] = x[i]^y[i]^u[i];
    }
  }
}


void sec_mul_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n){





  // ISW https://people.eecs.berkeley.edu/~daw/papers/privcirc-crypto03.pdf 

  if (n == 2){

#if defined(PQM4) && defined (ASM) 

 
  #define RAND_SEC_MUL 1
    uint16_t pool[RAND_SEC_MUL];
    (void)n; 

    for (int i = 0; i < RAND_SEC_MUL; i ++) {
      pool[i] = rand_u16();
    }
    asm_sec_mul_u16(z, x, y, pool);
    #undef RAND_SEC_ADD

#else

    z[0] = x[0] * y[0];
    z[1] = x[1] * y[1];
    
    uint16_t r = rand_u16();
    uint16_t tmp = r + (x[0] * y[1]);
    tmp += (x[1] * y[0]);
    z[0] += r;
    z[1] += tmp;
#endif

  } else {

    int i, j;
    uint16_t tmp, r;

    for(i = 0; i < n; i++){
      z[i] = x[i]*y[i];
    }

    for(i = 0; i < n; i++){
      for(j = i+1; j < n; j++){
        r = rand_u16();
        tmp = (r + x[i]*y[j]) + x[j]*y[i];
        z[i] -= r;
        z[j] += tmp;
      }
    }
  }
}




void sec_zero_test_bool_u16(uint16_t* out, uint16_t* in, int n){





if (n == 2){
    #define RAND_SEC_ZERO_TEST 9 // not sure about this value
    uint16_t pool[RAND_SEC_ZERO_TEST];
    (void)n; 

    for (int i = 0; i < RAND_SEC_ZERO_TEST; i ++) {
      pool[i] = rand_u16();
    }
    #undef RAND_SEC_ZERO_TEST
#if defined(PQM4) && defined (ASM)
    asm_sec_zero_test_bool_u16(out, in, pool);
#else
    order1_sec_zero_test_bool_u16(out, in, pool);
#endif

  } else {


      // https://tches.iacr.org/index.php/TCHES/article/view/9950/9453 Algo 14
      const int k=16, logk=4;
      int i, j;

      uint16_t z[n], temp[n];

      out[0] = (~in[0]) | ((1<<(1<<logk))-(1<<k));
      for(i=1; i < n; ++i) out[i] = in[i];

      for(i=0; i < logk; ++i){
        for(j=0; j < n; ++j) {
          z[j] = out[j] >> (1 << i);
        }
        full_bool_refresh_u16(z, n);
        sec_and_u16(temp, z, out, n);
        for(j=0; j < n; ++j){
          out[j] = temp[j]; 
        }
      }
      for(i=0; i < n; ++i) out[i] = (out[i])&1;

      full_bool_refresh_u16(out, n);
  
  }
}


#ifdef TESTS_BASICS

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


static int test_sec_mul(int n){
  int a = 5, b = 6;
  uint16_t x[n], y[n], z[n];

  arith_mask_value_u16(y, a, n);
  arith_mask_value_u16(x, b, n);

  sec_mul_u16(z, y, x, n);

  print_arith_masked_u16(z, n);

  if (arith_unmask_value_u16(z, n) != (a*b)){
    printf("Test sec_mul: Fail \n");
    return 0;
  }

  printf("Test sec_mul: Success \n");
  return 1;

}

static int test_sec_and(int n){
  int a = 5, b = 6;
  uint16_t x[n], y[n], z[n];

  bool_mask_value_u16(y, a, n);
  bool_mask_value_u16(x, b, n);

  sec_and_u16(z, x, y, n);

  //print_bool_masked_u16(z, n);

  if (bool_unmask_value_u16(z, n) != (a&b)){
    printf("Test sec_and: Fail \n");
    return 0;
  }

  printf("Test sec_and: Success \n");
  return 1;

}

static int test_sec_add(int n){
  int a = 5, b = 6;
  uint16_t x[n], y[n], z[n];

  bool_mask_value_u16(y, a, n);
  bool_mask_value_u16(x, b, n);

  sec_add_u16(z, x, y, n);

  //print_bool_masked_u16(z, n);

  if (bool_unmask_value_u16(z, n) != (a+b)){
    printf("Test sec_add: Fail \n");
    return 0;
  }

  printf("Test sec_add: Success \n");
  return 1;


}


static int test_AB(int n){
  int a;
  uint16_t x[n], y[n];


  for(a=0; a < 1<<16; ++a){
    arith_mask_value_u16(x, a, n);


    convert_AB_u16(y, x, n);



    if (bool_unmask_value_u16(y, n) != (a)){
      printf("Test sec_convertAB: Fail \n");
#if defined(PQM4)
      send_unsigned("a:", a);
#else
      printf("a: %i\n", a);
      print_arith_masked_u16(x, n);
      print_bool_masked_u16(y, n);
      
#endif
      return 0;
    }

  }

  printf("Test sec_convertAB: Success \n");
  return 1;
  

}

static int test_BA(int n){
  int a = 5;
  uint16_t x[n], y[n];


  for(a=0; a < (1<<6); ++a){

    bool_mask_value_u16(x, a, n);

      //print_bool_masked_u16(x, n);
    convert_BA_u16(y, x, n);
      //print_arith_masked_u16(y, n);

    if (arith_unmask_value_u16(y, n) != (a)){
      printf("Test sec_convertBA: Fail \n");
#if defined(PQM4)
      send_unsigned("a:", a);
#else
      print_bool_masked_u16(x, n);
      print_arith_masked_u16(y, n);
#endif
      return 0;
    }
  }

  printf("Test sec_convertBA: Success \n");
  return 1;
  

}


void test_zero_test_bool(int n){
  uint16_t x[n], y[n];

  bool_mask_value_u16(x, 0, n);
  sec_zero_test_bool_u16(y, x, n);
  printf("%i\n", bool_unmask_value_u16(y, n));


  bool_mask_value_u16(x, 123, n);

  sec_zero_test_bool_u16(y, x, n);
  printf("%i\n", bool_unmask_value_u16(y, n));

  bool_mask_value_u16(x, 43333, n);

  sec_zero_test_bool_u16(y, x, n);
  printf("%i\n", bool_unmask_value_u16(y, n));


}

int main(){
#if defined(PQM4)
  int n = 2;
  send_unsigned("M4 mode. N_SHARES =", (uint8_t)n);
#if defined(ASM)
  printf("ASM: on\n");
#else
  printf("ASM: off\n");
#endif
#else
  int n = 2;
  printf("x64 mode. N_SHARES = %d\n", n);
#endif
  printf("Hello world\n");
  init_rng();

  //test_sec_mul(n);
  test_sec_and(n);
  test_sec_add(n);
  test_AB(n);
  test_BA(n);
  //test_shift(n);
  test_zero_test_bool(n);

  return 1;
}


#endif



