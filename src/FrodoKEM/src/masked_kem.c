/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: Key Encapsulation Mechanism (KEM) based on Frodo
*********************************************************************************************/

#include <string.h>
#include "../sha3/fips202.h"

#ifdef DO_VALGRIND_CHECK
#include <valgrind/memcheck.h>
#endif

#include "masking_interface.h"
#include "frodo_macrify.h"

#if defined(PQM4)
    #include <hal.h>
    #include "sendfn.h"

    int randombytes(uint8_t* buf, size_t xlen);
#else
    #include "../random/random.h"
#endif

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // FrodoKEM's key generation
  // Outputs: public key pk = pk_seedA||pk_b                      (               BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 bytes)
  //          secret key sk = sk_s||pk_seedA||pk_b||sk_S||sk_pkh  (CRYPTO_BYTES + BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH bytes)
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_s = &sk[0];
    uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    uint8_t *sk_S = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[2*PARAMS_N*PARAMS_NBAR] = {0};                          // contains secret data
    uint16_t *E = (uint16_t *)&S[PARAMS_N*PARAMS_NBAR];                // contains secret data
    uint8_t randomness[CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A];   // contains secret data via randomness_s and randomness_seedSE
    uint8_t *randomness_s = &randomness[0];                            // contains secret data
    uint8_t *randomness_seedSE = &randomness[CRYPTO_BYTES];            // contains secret data
    uint8_t *randomness_z = &randomness[CRYPTO_BYTES + BYTES_SEED_SE];
    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];                     // contains secret data

    // Generate the secret value s, the seed for S and E, and the seed for the seed for A. Add seed_A to the public key
    if (randombytes(randomness, (size_t)(CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A)) != 0)
        return 1;
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
#endif
    shake(pk_seedA, BYTES_SEED_A, randomness_z, BYTES_SEED_A);

    // Generate S and E, and compute B = A*S + E. Generate A on-the-fly
    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, BYTES_SEED_SE);
    shake((uint8_t*)S, 2*PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < 2 * PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = LE_TO_UINT16(S[i]);
    }
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(E, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_as_plus_e(B, S, E, pk);

    // Encode the second part of the public key
    frodo_pack(pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, B, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

    // Add s, pk and S to the secret key
    memcpy(sk_s, randomness_s, CRYPTO_BYTES);
    memcpy(sk_pk, pk, CRYPTO_PUBLICKEYBYTES);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = UINT16_TO_LE(S[i]);
    }
    memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR);

    // Add H(pk) to the secret key
    shake(sk_pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);

    // Cleanup:
    clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)E, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE);
    clear_bytes(shake_input_seedSE, 1 + BYTES_SEED_SE);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
#endif
    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // FrodoKEM's key encapsulation
  // Input:   public key pk = pk_seedA||pk_b      (BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 bytes)
  // Outputs: ciphertext ct = ct_c1||ct_c2||salt  (               (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT bytes)
  //          shared key ss                       (CRYPTO_BYTES bytes)
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t V[PARAMS_NBAR*PARAMS_NBAR]= {0};                          // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t Bp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR];              // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR];           // contains secret data
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT];                // contains secret data via mu
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[BYTES_PKHASH];                                 // contains secret data
    uint8_t *salt = &G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES];                       // contains secret data
    uint8_t *seedSE = &G2out[0];                                       // contains secret data
    uint8_t *k = &G2out[BYTES_SEED_SE];                                // contains secret data
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];                // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[CRYPTO_CIPHERTEXTBYTES];                     // contains secret data
    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];                     // contains secret data

    // pkh <- G_1(pk), generate random mu and salt, compute (seedSE || k) = G_2(pkh || mu || salt)
    shake(pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    if (randombytes(mu, BYTES_MU + BYTES_SALT) != 0)
        return 1;
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(mu, BYTES_MU + BYTES_SALT);
    VALGRIND_MAKE_MEM_UNDEFINED(pk, CRYPTO_PUBLICKEYBYTES);
#endif
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);

    // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, BYTES_SEED_SE);
    shake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < (2 * PARAMS_N + PARAMS_NBAR) * PARAMS_NBAR; i++) {
        Sp[i] = LE_TO_UINT16(Sp[i]);
    }
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);
    frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);

    // Generate Epp, and compute V = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(V, B, Sp, Epp);

    // Encode mu, and compute C = V + enc(mu) (mod q)
    frodo_key_encode(C, (uint16_t*)mu);
    frodo_add(C, V, C);
    frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);

    // Append salt to ct and compute ss = F(ct_c1||ct_c2||salt||k)
    memcpy(&ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT], salt, BYTES_SALT);
    memcpy(Fin_ct, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(Fin_k, k, CRYPTO_BYTES);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    // Cleanup:
    clear_bytes((uint8_t *)V, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Ep, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Epp, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(mu, BYTES_MU);
    clear_bytes(G2out, BYTES_SEED_SE + CRYPTO_BYTES);
    clear_bytes(Fin_k, CRYPTO_BYTES);
    clear_bytes(shake_input_seedSE, 1 + BYTES_SEED_SE);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(mu, BYTES_MU);
    VALGRIND_MAKE_MEM_DEFINED(pk, CRYPTO_PUBLICKEYBYTES);
#endif
    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // FrodoKEM's key decapsulation
  // Inputs: ciphertext ct = ct_c1||ct_c2||salt                  (                              (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT bytes)
  //         secret key sk = sk_s||pk_seedA||pk_b||sk_S||sk_pkh  (CRYPTO_BYTES + BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH bytes)
  // Output: shared key ss                                       (CRYPTO_BYTES bytes)
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N*PARAMS_NBAR] = {0};

    uint16_t masked_W[PARAMS_NBAR*PARAMS_NBAR * N_SHARES] = {0};

    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t masked_CC[PARAMS_NBAR*PARAMS_NBAR*N_SHARES] = {0};

    ALIGN_HEADER(32) uint16_t masked_BBp[PARAMS_N*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t masked_Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*N_SHARES] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t *masked_Ep = (uint16_t *)&masked_Sp[PARAMS_N*PARAMS_NBAR*N_SHARES];              // contains secret data
    uint16_t *masked_Epp = (uint16_t *)&masked_Sp[2*PARAMS_N*PARAMS_NBAR*N_SHARES];           // contains secret data

    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    const uint8_t *salt = &ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    const uint16_t *sk_S = (uint16_t *) &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint16_t S[PARAMS_N * PARAMS_NBAR];                                // contains secret data
    uint16_t masked_S[PARAMS_N * PARAMS_NBAR * N_SHARES]; 
    uint8_t masked_sk_s[CRYPTO_BYTES * N_SHARES];
    const uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[BYTES_SEED_A];
    uint8_t masked_muprime[BYTES_MU*N_SHARES];

    uint8_t masked_Fin[(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES)*N_SHARES] = {0};

    uint16_t seedEP_masked[N_SHARES * ((2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR)];
    uint8_t G2in_masked[N_SHARES * (BYTES_PKHASH + BYTES_MU + BYTES_SALT)] = {0};
    uint8_t G2out_masked[N_SHARES * (BYTES_SEED_SE + CRYPTO_BYTES)] = {0};
    uint8_t kprime_masked[N_SHARES * CRYPTO_BYTES];  

    uint8_t masked_ss[CRYPTO_BYTES];
    uint8_t masked_selector[N_SHARES];

#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(sk, CRYPTO_SECRETKEYBYTES);
    VALGRIND_MAKE_MEM_UNDEFINED(ct, CRYPTO_CIPHERTEXTBYTES);
#endif

    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = LE_TO_UINT16(sk_S[i]);
    }

    mask_mat(masked_S , S, PARAMS_N * PARAMS_NBAR);
    mask_uint8_t_array(masked_sk_s, sk_s, CRYPTO_BYTES);

    // Compute W = C - Bp*S (mod q), and decode the randomness mu
    frodo_unpack(Bp, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ);
    //frodo_mul_bs(W, Bp, S);
    masked_frodo_mul_bs(masked_W, Bp, masked_S);

    //frodo_sub(W, C, W);
    half_masked_frodo_sub(masked_W, C, masked_W);

    //frodo_key_decode((uint16_t*)muprime, W);
    masked_frodo_key_decode((uint16_t*)masked_muprime, masked_W);

    // G2in_masked = pkh_0||mu_0||salt_0||00||mu_1||00||...||00||mu_n||00
    memset(G2in_masked, 0, N_SHARES * (BYTES_PKHASH + BYTES_MU));
    memcpy(G2in_masked, sk_pkh, BYTES_PKHASH); // copy pkh_0 = pkh into G2in
    for (int k = 0; k < N_SHARES; k++){     // copy all shares of muprime into G2in
        memcpy(G2in_masked + BYTES_PKHASH + k* (BYTES_PKHASH + BYTES_MU + BYTES_SALT), masked_muprime + k * BYTES_MU, BYTES_MU);
    }
    memcpy(G2in_masked + BYTES_PKHASH + BYTES_MU, salt, BYTES_SALT); // copy salt_0 = salt into G2in

    // Generate (seedSE' || k') = G_2(pkh || mu' || salt)
    masked_shake(G2out_masked, BYTES_SEED_SE + CRYPTO_BYTES, G2in_masked, BYTES_PKHASH + BYTES_MU + BYTES_SALT);
    for (int k = 0; k < N_SHARES; k++) {    // copy all shares of seedSE into G2in
        memcpy(G2in_masked + 1 + k * (1 + BYTES_SEED_SE), G2out_masked + k * (BYTES_SEED_SE + CRYPTO_BYTES), BYTES_SEED_SE);
        G2in_masked[k * (1 + BYTES_SEED_SE)] = 0;
        memcpy(kprime_masked + k * (CRYPTO_BYTES), G2out_masked + k * (BYTES_SEED_SE + CRYPTO_BYTES) + BYTES_SEED_SE, CRYPTO_BYTES);
    }
    G2in_masked[0] = 0x96; // copy 0x96 into G2in

    // Generate Sp || Ep || Epp = G_2(0x96||seedSE)
    masked_shake((uint8_t *)seedEP_masked, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), G2in_masked, 1 + BYTES_SEED_SE);
    for (int k = 0; k < N_SHARES; k++)
    {
        for (int i = 0; i < PARAMS_N*PARAMS_NBAR; i++) {
            masked_Sp[i + k*PARAMS_N*PARAMS_NBAR] = LE_TO_UINT16(seedEP_masked[i + k*((2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR)]);
            masked_Ep[i + k*PARAMS_N*PARAMS_NBAR] = LE_TO_UINT16(seedEP_masked[i + PARAMS_N*PARAMS_NBAR + k*((2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR)]);
        }
        for (int i = 0; i < PARAMS_NBAR*PARAMS_NBAR; i++) {
            masked_Epp[i + k*PARAMS_NBAR*PARAMS_NBAR] = LE_TO_UINT16(seedEP_masked[i + 2*PARAMS_N*PARAMS_NBAR + k*((2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR)]);
        }
    }

    masked_frodo_sample_n(masked_Sp, PARAMS_N*PARAMS_NBAR);

    masked_frodo_sample_n(masked_Ep, PARAMS_N*PARAMS_NBAR);
    masked_frodo_sample_n(masked_Epp, PARAMS_NBAR*PARAMS_NBAR);

    masked_frodo_mul_add_sa_plus_e(masked_BBp, masked_Sp, masked_Ep, pk_seedA);

    // Generate Epp, and compute W = Sp*B + Epp
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);

    masked_frodo_mul_add_sb_plus_e(masked_W, B, masked_Sp, masked_Epp);
    
    // Encode mu, and compute CC = W + enc(mu') (mod q)
    masked_frodo_key_encode(masked_CC, (uint16_t*) masked_muprime);

    masked_frodo_add(masked_CC, masked_W, masked_CC);


    // If (Bp == BBp & C == CC) then ss = F(ct || k'), else ss = F(ct || s)
    // Needs to avoid branching on secret data using constant-time implementation.
    masked_frodo_compare(masked_BBp, Bp, masked_CC, C, masked_selector);
    masked_ct_select(masked_Fin, ct, kprime_masked, masked_sk_s, masked_selector);

    masked_shake(masked_ss, CRYPTO_BYTES, masked_Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    unmask_uint8_t_array(ss, masked_ss, CRYPTO_BYTES);

    // Cleanup:
    /* [TODO] clean up masked variables */
    clear_bytes((uint8_t *)masked_S, PARAMS_N * PARAMS_NBAR * N_SHARES*sizeof(uint16_t));

#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(sk, CRYPTO_SECRETKEYBYTES);
    VALGRIND_MAKE_MEM_DEFINED(ct, CRYPTO_CIPHERTEXTBYTES);
#endif
    return 0;
}
