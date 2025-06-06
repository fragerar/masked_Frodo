#ifndef MASKING_INTERFACE_H
#define MASKING_INTERFACE_H
#include <stdint.h>


int frodo_mul_add_as_plus_e(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A);
int frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, uint16_t *e, const uint8_t *seed_A);
void frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s) ;
void frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) ;
void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b);
void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b);



void masked_frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s);
void masked_frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b);
void half_masked_frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b);

void masked_frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, uint16_t *e, const uint8_t *seed_A);
void masked_frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e);

void masked_frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b);
void masked_frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b);

void masked_frodo_key_encode(uint16_t *out, const uint16_t *in);
void masked_frodo_key_decode(uint16_t *out, const uint16_t *in);

void masked_frodo_compare(uint16_t* masked_BBp, uint16_t* Bp, uint16_t* masked_CC, uint16_t* C, uint8_t* masked_selector);
void masked_ct_select(uint8_t* masked_Fin, const uint8_t* ct, uint8_t* masked_kprime, uint8_t* masked_sks, uint8_t* masked_selector);



// ---------------------------------------------

void mask_mat(uint16_t* masked_mat, uint16_t* mat, int size);
void unmask_mat(uint16_t* mat, uint16_t* masked_mat, int size);

void print_masked_mat(uint16_t* masked_mat, int size);
void print_mat(uint16_t* mat, int size);

void mask_uint8_t_array(uint8_t* masked_s, const uint8_t* s, int size);
void unmask_uint8_t_array(uint8_t* s, const uint8_t* masked_s, int size);

void print_uint8_t_array(uint8_t* s, int size);
void print_masked_uint8_t_array(uint8_t* s, int size);

#endif