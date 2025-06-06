/*  modified version of the file written in 2016-2018 by David Blackman
 and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* This is xoroshiro128+ 1.0, our best and fastest small-state generator
   for floating-point numbers, but its state space is large enough only
   for mild parallelism. We suggest to use its upper bits for
   floating-point generation, as it is slightly faster than
   xoroshiro128++/xoroshiro128**. It passes all tests we are aware of
   except for the four lower bits, which might fail linearity tests (and
   just those), so if low linear complexity is not considered an issue (as
   it is usually the case) it can be used to generate 64-bit outputs, too;
   moreover, this generator has a very mild Hamming-weight dependency
   making our test (http://prng.di.unimi.it/hwd.php) fail after 5 TB of
   output; we believe this slight bias cannot affect any application. If
   you are concerned, use xoroshiro128++, xoroshiro128** or xoshiro256+.

   We suggest to use a sign test to extract a random Boolean value, and
   right shifts to extract subsets of bits.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. 

   NOTE: the parameters (a=24, b=16, b=37) of this version give slightly
   better results in our test than the 2016 version (a=55, b=14, c=36).
*/

static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}


static uint64_t state[2];


void init_rng(){
  //state[0] = 0xA5A5A5A5A5A5A5A5LLU;
  //state[1] = 0xA5A5A5A5A5A5A5A5LLU;

  srand(time(NULL));
  state[0] = (((uint64_t) rand()) << 32) | ((uint64_t) rand()); 
  state[1] = (((uint64_t) rand()) << 32) | ((uint64_t) rand()); 

}


uint64_t next(void) {
	const uint64_t s0 = state[0];
	uint64_t s1 = state[1];
	const uint64_t result = s0 + s1;

	s1 ^= s0;
	state[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16); // a, b
	state[1] = rotl(s1, 37); // c

	return result;
}



