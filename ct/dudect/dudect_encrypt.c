/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_encrypt.c -- dudect main loop driving fhe.Encryptor.EncryptSafe
 * through the cgo bridge in encrypt_ct.go.
 *
 * dudect API contract: the user provides do_one_computation(data) and
 * prepare_inputs(cfg, input, classes); dudect's `dudect_main` invokes
 * them via the extern declarations at the bottom of dudect.h.
 *
 * We define DUDECT_IMPLEMENTATION exactly once before including the
 * header so the whole library compiles into this translation unit.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported by libtfhe_encrypt (encrypt_ct.go). */
extern int    tfhe_encrypt_ct_setup(void);
extern size_t tfhe_encrypt_ct_input_size(void);
extern void   tfhe_encrypt_ct(uint8_t *data);

static size_t g_chunk_size = 0;

/*
 * dudect API hook: populate cfg->number_measurements samples of
 * cfg->chunk_size bytes each, and assign each sample a binary class
 * label (0 = fixed class A, 1 = random class B).
 *
 * class A: byte 0 = 0  (encrypt false)
 * class B: byte 0 = uniformly-random byte (encrypt random bit)
 */
void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            slot[0] = 0;  /* always 0 in class A */
        } else {
            uint8_t r;
            randombytes(&r, 1);
            slot[0] = r;
        }
    }
}

/*
 * dudect API hook: one measurement sample. Must depend on `data` so
 * the compiler cannot dead-code-eliminate the body, must NOT branch
 * on `data` (or we measure our own branch), and must return a
 * uint8_t that flows out of the function so the result is observed.
 */
uint8_t do_one_computation(uint8_t *data) {
    tfhe_encrypt_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = tfhe_encrypt_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "tfhe_encrypt_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = tfhe_encrypt_ct_input_size();
    if (g_chunk_size == 0) {
        fprintf(stderr, "tfhe_encrypt_ct_input_size returned 0\n");
        return 1;
    }

    /*
     * SMOKE-TEST default (10 000 samples per batch). The full NIST
     * submission run is 10^9 samples on a quiet, CPU-pinned host;
     * override via env vars:
     *   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_encrypt
     */
    const char *env_samples  = getenv("DUDECT_SAMPLES");
    const char *env_batches  = getenv("DUDECT_MAX_BATCHES");
    size_t samples = env_samples  ? (size_t)atoll(env_samples)  : 10000;
    size_t batches = env_batches  ? (size_t)atoll(env_batches)  : 100;

    dudect_config_t cfg = {
        .chunk_size         = g_chunk_size,
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
        fprintf(stderr, "VERDICT: leakage detected in tfhe.Encrypt\n");
        return 2;
    }
    fprintf(stdout, "VERDICT: no leakage detected within budget\n");
    return 0;
}
