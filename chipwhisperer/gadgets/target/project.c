#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "utils.h"

#define N_SHARES 2
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)

#ifdef PLAIN_C
    #define CALL(func) order1##func
#elif defined(NAIVE_ASM)
    #define CALL(func) naive_asm##func
#else
    #define CALL(func) asm##func
#endif

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    volatile uint16_t x_masked[N_SHARES], y_masked[N_SHARES], y;
    volatile uint16_t z_masked[N_SHARES];
    uint8_t res[2];
    int start_rand = 4;

    x_masked[0] = ((uint16_t)pt[0] << 8) | pt[1];
    x_masked[1] = ((uint16_t)pt[2] << 8) | pt[3];
#if (defined(AND) || defined(ADD))
    z_masked[0] = ((uint16_t)pt[4] << 8) | pt[5];
    z_masked[1] = ((uint16_t)pt[6] << 8) | pt[7];
    start_rand += 4;
#endif

    for (volatile int k = 0; k < 1000; k++) {;} // to clean the power trace

    trigger_high();

#if defined(AB)
    CALL(_convert_AB_u16)(y_masked, x_masked, pt+start_rand);
#elif defined(BA)
    CALL(_convert_BA_u16)(y_masked, x_masked, pt+start_rand);
#elif defined(AND)
    CALL(_sec_and_u16)(y_masked, z_masked, x_masked, pt+start_rand);
#elif defined(ADD)
    CALL(_sec_add_u16)(y_masked, z_masked, x_masked, pt+start_rand);
#elif defined(ZERO)
    CALL(_sec_zero_test_bool_u16)(y_masked, x_masked, pt+start_rand);
#endif

    trigger_low();

    for (volatile int k = 0; k < 100; k++) {;}  // to clean the power trace

#if (defined(AB) || defined(AND) || defined(ADD) || defined(ZERO))
    y = (y_masked[0] ^ y_masked[1]) % PARAMS_Q;
#elif defined(BA)
    y = (y_masked[0] + y_masked[1]) % PARAMS_Q;
#endif

    res[0] = y >> 8;
    res[1] = y & 0xff;
    simpleserial_put('r', 2, res);

    return 0x00;
}



int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

#if (defined(AB) || defined (BA) || defined(ZERO))
    simpleserial_addcmd('p', 4+RAND,  get_pt);
#elif (defined(AND) || defined(ADD))
    simpleserial_addcmd('p', 8+RAND,  get_pt);
#endif

    while(1)
        simpleserial_get();
}