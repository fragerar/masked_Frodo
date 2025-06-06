#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

uint16_t rand_u16();
uint32_t rand_u32();



// XoroshirO128+

extern uint64_t state[2];
void init_rng();
uint64_t next(void);


#endif