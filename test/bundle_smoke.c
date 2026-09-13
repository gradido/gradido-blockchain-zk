/* Smoke test of the shielded transfer C ABI.
 *
 *   cargo build --release
 *   cargo run --release --example wire_sample /tmp/sample
 *   gcc -std=c11 -Iinclude test/bundle_smoke.c -o bundle_smoke \
 *       target/release/libgradido_blockchain_zk.a -lpthread -ldl -lm
 *   ./bundle_smoke /tmp/sample
 */
#include "gradido_blockchain_zk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *slurp(const char *dir, const char *name, size_t *len) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    rewind(f);
    uint8_t *buf = malloc(*len);
    if (fread(buf, 1, *len, f) != *len) { exit(2); }
    fclose(f);
    return buf;
}

static int failures = 0;
static void expect(const char *what, int32_t got, int32_t want) {
    printf("%-44s %4d %s\n", what, got, got == want ? "ok" : "FAILED");
    if (got != want) failures++;
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    size_t body_len, auth_len, sighash_len, community_len;
    uint8_t *body = slurp(dir, "shielded_bundle.bin", &body_len);
    uint8_t *auth = slurp(dir, "shielded_authorization.bin", &auth_len);
    uint8_t *sighash = slurp(dir, "sighash.bin", &sighash_len);
    uint8_t *community = slurp(dir, "community.bin", &community_len);
    const uint64_t now = 1800000000ULL;
    uint8_t effects[GRDZK_BUNDLE_EFFECTS_SIZE];

    expect("bundle init", grdzk_bundle_init(), GRDZK_OK);
    memset(effects, 0, sizeof effects);
    expect("valid bundle", grdzk_bundle_verify(body, body_len, auth, auth_len, community, now, sighash, effects), GRDZK_OK);
    size_t zero_bytes = 0;
    for (size_t i = 0; i < sizeof effects; i++) zero_bytes += effects[i] == 0;
    printf("%-44s %4d %s\n", "effects written", (int)(sizeof effects - zero_bytes), zero_bytes < 16 ? "ok" : "FAILED");
    if (zero_bytes >= 16) failures++;

    /* signatures cover the sighash */
    uint8_t other_sighash[32];
    memcpy(other_sighash, sighash, 32);
    other_sighash[0] ^= 1;
    expect("other sighash", grdzk_bundle_verify(body, body_len, auth, auth_len, community, now, other_sighash, effects),
           GRDZK_ERR_SPEND_AUTH);

    /* the proof computes the decay for `now` */
    expect("other created_at", grdzk_bundle_verify(body, body_len, auth, auth_len, community, now + 3600, sighash, effects),
           GRDZK_ERR_PROOF);

    /* a flipped proof byte */
    auth[20] ^= 1;
    int32_t rc = grdzk_bundle_verify(body, body_len, auth, auth_len, community, now, sighash, effects);
    printf("%-44s %4d %s\n", "flipped proof byte", rc, rc != GRDZK_OK ? "ok" : "FAILED");
    if (rc == GRDZK_OK) failures++;
    auth[20] ^= 1;

    /* one byte appended to the proof: halo2 alone would still accept it */
    uint8_t *longer = malloc(auth_len + 1);
    memcpy(longer, auth, auth_len);
    longer[auth_len] = 0;
    expect("trailing byte in authorization", grdzk_bundle_verify(body, body_len, longer, auth_len + 1, community, now, sighash, effects),
           GRDZK_ERR_WIRE);
    free(longer);

    expect("truncated bundle", grdzk_bundle_verify(body, body_len - 5, auth, auth_len, community, now, sighash, effects),
           GRDZK_ERR_WIRE);
    expect("null pointer", grdzk_bundle_verify(NULL, 0, auth, auth_len, community, now, sighash, effects),
           GRDZK_ERR_NULL_POINTER);

    /* the sighash of a body is stable and depends on every byte */
    uint8_t h1[32], h2[32], body_copy[4] = {1, 2, 3, 4};
    expect("body sighash", grdzk_body_sighash(body_copy, 4, h1), GRDZK_OK);
    body_copy[3] = 5;
    grdzk_body_sighash(body_copy, 4, h2);
    int differs = memcmp(h1, h2, 32) != 0;
    printf("%-44s %4d %s\n", "sighash depends on the body", differs, differs ? "ok" : "FAILED");
    if (!differs) failures++;

    /* tree: the root changes with every commitment */
    GrdzkTree *tree = grdzk_tree_new();
    uint8_t empty_root[32], root[32], cm[32] = {42};
    expect("tree root", grdzk_tree_root(tree, empty_root), GRDZK_OK);
    uint64_t size = 99;
    expect("tree size", grdzk_tree_size(tree, &size), GRDZK_OK);
    expect("empty tree has size 0", (int32_t)size, 0);
    expect("tree append", grdzk_tree_append(tree, cm), GRDZK_OK);
    expect("tree checkpoint", grdzk_tree_checkpoint(tree), GRDZK_OK);
    grdzk_tree_root(tree, root);
    int changed = memcmp(empty_root, root, 32) != 0;
    printf("%-44s %4d %s\n", "root changed", changed, changed ? "ok" : "FAILED");
    if (!changed) failures++;
    uint8_t not_canonical[32];
    memset(not_canonical, 0xff, 32);
    expect("non canonical commitment", grdzk_tree_append(tree, not_canonical), GRDZK_ERR_BAD_VALUE);
    grdzk_tree_free(tree);

    /* creation commitment rejects a garbage address */
    uint8_t garbage[43], zero[32] = {0}, out[32];
    memset(garbage, 0xee, 43);
    expect("creation with bad address",
           grdzk_creation_commitment(community, 10000000, now, 0, garbage, 0, zero, zero, out),
           GRDZK_ERR_BAD_ADDRESS);

    printf("%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
