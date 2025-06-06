#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>



void linear_arith_refresh_u16(uint16_t* x, int n);
void full_arith_refresh_u16(uint16_t* x, int n);
void linear_bool_refresh_u16(uint16_t* x, int n);
void full_bool_refresh_u16(uint16_t* x, int n);


void arith_mask_value_u16(uint16_t* y, uint16_t x, int n);
void arith_mask_value_u16_array(uint16_t* y, uint16_t* x, int size, int n);
void bool_mask_value_u16(uint16_t* y, uint16_t x, int n);

uint16_t arith_unmask_value_u16(const uint16_t* y, int n);
void arith_unmask_value_u16_array(uint16_t* y, const uint16_t* x, int size, int n);
uint16_t bool_unmask_value_u16(const uint16_t* y, int n);
uint64_t bool_unmask_value_u64(const uint64_t* y, int n);

void print_arith_masked_u16_array(const uint16_t* x, int size, int n);
void print_arith_masked_u16(const uint16_t* x, int n);
void print_bool_masked_u16(const uint16_t* x, int n);
void print_bool_masked_u64(const uint64_t* x, int n);

void print_masked_bitstring(const uint8_t* s, int size, int n);

void mask_bitstring(uint8_t* masked_s, const uint8_t* s, int size, int n);
void unmask_bitstring(uint8_t* unmasked_s, const uint8_t* masked_s, int size, int n);



#endif