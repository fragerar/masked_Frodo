#ifndef BASICS_H
#define BASICS_H

#include <stdint.h>

#define ASM
//#define TESTS_BASICS

void convert_AB_u16(uint16_t* y, const uint16_t* x, int n); 
void convert_BA_u16(uint16_t* y, const uint16_t* x, int n);


void sec_and_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n);
void sec_and_u8(uint8_t* z, const uint8_t* x, const uint8_t* y, int n);

void sec_add_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n);
void sec_mul_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, int n);


void sec_zero_test_bool_u16(uint16_t* out, uint16_t* in, int n);


void order1_convert_AB_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool);
void order1_convert_BA_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool);
void order1_sec_and_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t* pool);
void order1_sec_add_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t *pool);
void order1_sec_zero_test_bool_u16(uint16_t* out, uint16_t* in, const uint16_t *pool);

#if defined(PQM4) && defined (ASM)

void asm_convert_AB_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool);
void asm_convert_BA_u16(uint16_t* y, const uint16_t* x, const uint16_t *pool);
void asm_sec_and_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t* pool);
void asm_sec_and_u8(uint8_t* z, const uint8_t* x, const uint8_t* y, const uint8_t* pool);
void asm_sec_add_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t *pool);
void asm_sec_mul_u16(uint16_t* z, const uint16_t* x, const uint16_t* y, const uint16_t *pool);
void asm_sec_zero_test_bool_u16(uint16_t* out, uint16_t* in, const uint16_t *pool);

#endif

#endif