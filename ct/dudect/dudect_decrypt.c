/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_decrypt.c -- dudect main loop driving fhe.Decryptor.Decrypt
 * through the cgo bridge in decrypt_ct.go.
 *
 * Decrypt is the most CT-critical TFHE routine -- a timing leak
 * here leaks bits of the secret key. The harness uses a pool of
 * valid ciphertexts pre-generated under the same secret key, with
 * varying plaintext bits, so any timing difference is a real
 * secret-content-dependent signal in Decrypt.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported by libtfhe_decrypt (decrypt_ct.go). */
extern int    tfhe_decrypt_ct_setup(void);
extern size_t tfhe_decrypt_ct_pool_size(void);
extern size_t tfhe_decrypt_ct_input_size(void);
extern void   tfhe_decrypt_ct(uint8_t *data);

static size_t g_chunk_size = 0;
static size_t g_pool_size  = 0;

void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            /* class A: pool[0] every time. */
            slot[0] = 0;
            slot[1] = 0;
            slot[2] = 0;
            slot[3] = 0;
        } else {
            /* class B: uniformly-chosen pool index. */
            uint8_t pick_buf[8];
            randombytes(pick_buf, sizeof pick_buf);
            uint64_t pick = 0;
            for (size_t k = 0; k < sizeof pick_buf; k++) {
                pick = (pick << 8) | pick_buf[k];
            }
            uint32_t idx = (uint32_t)(pick % g_pool_size);
            slot[0] = (uint8_t)(idx >> 24);
            slot[1] = (uint8_t)(idx >> 16);
            slot[2] = (uint8_t)(idx >> 8);
            slot[3] = (uint8_t)(idx);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    tfhe_decrypt_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = tfhe_decrypt_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "tfhe_decrypt_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = tfhe_decrypt_ct_input_size();
    g_pool_size  = tfhe_decrypt_ct_pool_size();
    if (g_chunk_size == 0 || g_pool_size == 0) {
        fprintf(stderr, "tfhe_decrypt_ct sizes returned 0\n");
        return 1;
    }

    const char *env_samples = getenv("DUDECT_SAMPLES");
    const char *env_batches = getenv("DUDECT_MAX_BATCHES");
    size_t samples = env_samples ? (size_t)atoll(env_samples) : 10000;
    size_t batches = env_batches ? (size_t)atoll(env_batches) : 100;

    dudect_config_t cfg = {
        .chunk_size          = g_chunk_size,
        .number_measurements = samples,
        .max_number_batches  = batches,
    };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &cfg);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        fprintf(stderr, "VERDICT: leakage detected in tfhe.Decrypt\n");
        return 2;
    }
    fprintf(stdout, "VERDICT: no leakage detected within budget\n");
    return 0;
}
