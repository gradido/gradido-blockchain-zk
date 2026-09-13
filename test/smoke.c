/* Smoke test for the C ABI. Build & run: see README.md */
#include "gradido_blockchain_zk.h"

#include <stdio.h>
#include <string.h>

/* write a small unsigned value as 32-byte little-endian */
static void put_u64(uint8_t* dst, uint64_t v)
{
    memset(dst, 0, GRDZK_VALUE_BYTES);
    for (int i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)(v >> (8 * i));
    }
}

int main(void)
{
    printf("gradido-blockchain-zk version %s\n", grdzk_version());

    if (grdzk_init() != GRDZK_OK) {
        fprintf(stderr, "grdzk_init failed\n");
        return 1;
    }

    uint8_t inputs[GRDZK_N_IN * GRDZK_VALUE_BYTES];
    uint8_t outputs[GRDZK_N_OUT * GRDZK_VALUE_BYTES];
    uint8_t sighash[GRDZK_VALUE_BYTES];

    /* 700000 + 300000 == 999000 + 1000 */
    put_u64(&inputs[0 * GRDZK_VALUE_BYTES], 700000);
    put_u64(&inputs[1 * GRDZK_VALUE_BYTES], 300000);
    put_u64(&outputs[0 * GRDZK_VALUE_BYTES], 999000);
    put_u64(&outputs[1 * GRDZK_VALUE_BYTES], 1000);
    put_u64(sighash, 0xC0FFEE);

    grdzk_buffer proof = {0};
    int32_t rc = grdzk_prove(inputs, GRDZK_N_IN, outputs, GRDZK_N_OUT, sighash, &proof);
    if (rc != GRDZK_OK) {
        fprintf(stderr, "grdzk_prove failed: %d\n", rc);
        return 1;
    }
    printf("proof: %zu bytes\n", proof.len);

    rc = grdzk_verify(proof.data, proof.len, sighash);
    printf("verify (correct sighash): %s\n", rc == GRDZK_OK ? "OK" : "FAILED");
    if (rc != GRDZK_OK) { return 1; }

    /* the proof must not verify against a different transaction body */
    uint8_t other[GRDZK_VALUE_BYTES];
    put_u64(other, 0xBADBAD);
    rc = grdzk_verify(proof.data, proof.len, other);
    printf("verify (wrong sighash):   %s\n", rc == GRDZK_ERR_VERIFY_FAILED ? "rejected (expected)" : "UNEXPECTED");
    if (rc != GRDZK_ERR_VERIFY_FAILED) { return 1; }

    grdzk_buffer_free(&proof);

    /* an unbalanced witness must not produce a proof at all */
    put_u64(&outputs[1 * GRDZK_VALUE_BYTES], 1001);
    grdzk_buffer bad = {0};
    rc = grdzk_prove(inputs, GRDZK_N_IN, outputs, GRDZK_N_OUT, sighash, &bad);
    printf("prove (unbalanced):       %s\n", rc == GRDZK_ERR_UNBALANCED ? "rejected (expected)" : "UNEXPECTED");
    grdzk_buffer_free(&bad);
    if (rc != GRDZK_ERR_UNBALANCED) { return 1; }

    printf("\nall C ABI checks passed\n");
    return 0;
}
