// Generates test vectors (gdd, duration, decayed, decayed_windowed) from the real unit.c.
// Output: decay_vectors.csv, used by src/tests_decay.rs and the decay chip tests. Build from the
// repository root with checkouts of gradido-blockchain-core and arnm:
//   C=../gradido-blockchain-core; A=../arnm
//   gcc -O2 -std=c11 -I$C/include -I$C/third_party -I$A/include test/gen_decay_vectors.c \
//       $C/src/data/unit.c $C/third_party/fp256/src/*.c $A/src/converter.c -lm -o gen
//   ./gen > test/decay_vectors.csv
#include "gradido_blockchain_core/data/unit.h"
#include <stdio.h>
#include <stdint.h>

static uint64_t s = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

static void emit(int64_t gdd, int64_t dur) {
  printf("%lld,%lld,%lld,%lld\n", (long long)gdd, (long long)dur,
         (long long)grdd_unit_calculate_decay(gdd, dur),
         (long long)grdd_unit_calculate_decay_windowed(gdd, dur));
}

int main(void) {
  const int64_t Y = 31556952;
  int64_t gdds[] = {0, 1, 2, 3, 5, 9999, 10000, 123456789, 10000000, 1000000000000LL,
                    (int64_t)1 << 40, INT64_MAX / 2, INT64_MAX - 1, INT64_MAX};
  int64_t durs[] = {0, 1, 2, 59, 3600, 86400, Y - 1, Y, Y + 1, 2 * Y, 2 * Y + 12345,
                    10 * Y + 7, 62 * Y + Y / 2, 63 * Y, 63 * Y + 1, 64 * Y, 200 * Y + 5, 120};
  for (unsigned i = 0; i < sizeof gdds / sizeof *gdds; ++i)
    for (unsigned j = 0; j < sizeof durs / sizeof *durs; ++j) emit(gdds[i], durs[j]);
  for (int i = 0; i < 4000; ++i) {
    uint64_t r = rnd();
    int64_t gdd;
    switch (r % 4) {
      case 0: gdd = (int64_t)(rnd() % 100000000ULL); break;            // up to 10k GDD
      case 1: gdd = (int64_t)(rnd() % 10000000000000ULL); break;       // up to 1e9 GDD
      case 2: gdd = (int64_t)(rnd() >> 1); break;                      // full int64 range
      default: gdd = (int64_t)(rnd() % 2000000ULL); break;             // small amounts
    }
    int64_t dur;
    switch ((r >> 8) % 4) {
      case 0: dur = (int64_t)(rnd() % (uint64_t)Y); break;             // under a year
      case 1: dur = (int64_t)(rnd() % (uint64_t)(5 * Y)); break;
      case 2: dur = (int64_t)(rnd() % (uint64_t)(70 * Y)); break;
      default: dur = (int64_t)(rnd() % 7200ULL); break;                // within two hours
    }
    emit(gdd, dur);
  }
  return 0;
}
