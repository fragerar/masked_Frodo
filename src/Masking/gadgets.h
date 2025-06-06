#ifndef GADGETS_H
#define GADGETS_H

#include <stdint.h>
#include <stddef.h>


void masked_key_encode(uint16_t *out, const uint16_t *in, int n);
void masked_key_decode(uint16_t *out, const uint16_t *in, int n);
void masked_compare(uint16_t* masked_BBp, uint16_t* Bp, uint16_t* masked_CC, uint16_t* C, uint8_t* masked_selector, int n);
void masked_sample_n(uint16_t *s, const size_t len, unsigned int n);




#endif