#include "random.h"


uint16_t rand_u16(){

  return (uint16_t) (next() & 0xFFFF);

}
uint32_t rand_u32(){

  return (uint32_t) (next() & 0xFFFFFFFF);
}


