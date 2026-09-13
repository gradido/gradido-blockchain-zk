# gradido-blockchain-zk

Shielded transfers for the Gradido blockchain, after the Zcash Orchard model: halo2 circuits
with the exact decay of Gradido, keys, addresses, note encryption and signatures, a C ABI for
[`gradido_node`](https://github.com/gradido/gradido_node) and a WebAssembly signer for wallets.

Stack per **E1**: halo2 on Pasta curves with IPA — **no trusted setup**.
Design decisions and roadmap (German): [`privacy_todo.md`](privacy_todo.md), referred to as E1–E17
throughout the code.

| used by | through |
|---|---|
| `gradido_node` | C ABI (`include/gradido_blockchain_zk.h`): verify transfers, note commitment tree, creations |
| community server | Rust: build and prove transfers, signing requests |
| wallet app / browser extension | WebAssembly (`src/wasm.rs`): keys, addresses, review and sign |

Related repositories: [`gradido-blockchain-core`](https://github.com/gradido/gradido-blockchain-core)
(`unit.c`, the decay this crate reproduces bit for bit, and `grdd_unit_calculate_decay_windowed`),
[`gradido_protocol`](https://github.com/gradido/gradido_protocol) (`shielded.proto`).

## Status

Not reviewed, not audited. It started as a skeleton, `circuit/value_balance.rs` with
`grdzk_prove`/`grdzk_verify`: value conservation over anchored values (the dropped decision
E2). That circuit is kept only as the first measurement and plays no role in a transfer.

What a transfer uses today is one full shielded action with decay inside the proof:

* `note.rs` — the note of E4 with its Poseidon commitment and nullifier
* `circuit/note_chip.rs` — the same in circuit, binding every field to the cell the rest of the
  circuit uses
* `circuit/decay_chip.rs` — `grdd_unit_calculate_decay` from unit.c, bit for bit, and the
  windowed variant `grdd_unit_calculate_decay_windowed`
* `circuit/action_slice.rs` — spend one note, create one note, with Merkle path, nullifier,
  address check, value commitment and spend authorisation

Around the circuit sit the parts a transfer needs to actually happen:

* `keys.rs` — spending key, the custody split of E5 (spending key on the device, `fvk` on the server),
  diversified addresses, and the monthly creation address of E7
* `address.rs` — address encoding after ZIP 316: Bech32m over F4Jumble, with the HRP padding
* `note_encryption.rs` — `zcash_note_encryption` with a Gradido `Domain`
* `memo.rs` — the memo of E15, sealed under its own key and bound by `memo_cm`
* `signature.rs` — value commitment plus spend authorisation and binding signature on RedPallas
  (`reddsa`)

`tests_e2e.rs` walks one transfer through all of it: address, note, tree, proof, verification,
encryption, the recipient rebuilding the note, the memo, and both signatures.

And around that, a complete shielded transfer:

* `tree.rs` — note commitment tree (`bridgetree` with the circuit's Sinsemilla hash), anchor
  history, nullifier set
* `bundle.rs` — build a transfer (pair spends and outputs, pad with dummies, one proof for all
  actions), authorise it along the custody split, verify and apply it to a ledger
* `wire.rs` — the bundle in the wire format of `shielded.proto`, decoded strictly
* `signer.rs` — the device side of E5: check a transfer against the spending key, show what it
  pays, sign it
* `wasm.rs` — the signer as a JavaScript module for a wallet app or browser extension
* `ffi.rs` — C ABI for the node: verify a bundle, keep the tree, compute a creation commitment
* `circuit/fixed_bases_generated.rs` — the ECC window tables as constants; searching them at
  runtime used to cost 160 s before the first proof

**Not implemented yet:** cross community transfers (`cross_community_cv`), note expiry and tree
epochs (E10), persisting the tree in the node (it is rebuilt from the stored commitments).

## Measurements

On this machine (Ryzen 7 5700G, release build, 16 threads):

| | |
|---|---|
| one action, windowed decay | k = 11, 2034 / 2048 rows, prove ~400 ms, verify ~5 ms, proof 5408 B |
| transfer with 2 actions | build and prove ~700 ms, decode and verify 7 ms, 9.9 KB on the wire |
| keygen | ~1 s once per process (the fixed base tables are constants) |

Details in the sections below. The skeleton circuit (`examples/timing.rs`) proved in ~130 ms
with a 2560 byte proof; it has no Merkle path, no keys and no decay.

## Decay in the circuit (`circuit/decay_bench.rs`)

Three strategies for decay, built on the same gadgets so their cost is comparable:

| mode | note stores | circuit does |
|---|---|---|
| E2 anchored | `u = amount * 2^((t - T0) / year)`, grows without bound | only adds |
| way 2 epoch | value anchored to its own year, `< 2^96` | divides by `2^years` |
| way 1 exact | nominal int64 value + timestamp | `grdd_unit_calculate_decay` from unit.c, bit for bit |

Way 1 is checked against the real C implementation: `test/decay_vectors.csv` holds 4252
vectors produced by `test/gen_decay_vectors.c` from `unit.c` (edge cases, values up to
`INT64_MAX`, durations up to 200 years). `crate::decay` matches all of them natively, and the
circuit matches all of them in the MockProver (`cargo test --release -- --ignored`).

```sh
cargo run --release --example decay_timing
```

Measured on this machine (16 threads), 2 in / 2 out:

| | k = 9 (smallest fit) | k = 11 | k = 12 | k = 13 |
|---|---|---|---|---|
| E2 anchored | 99 ms | 220 ms | 394 ms | 708 ms |
| way 2 epoch | 105 ms | 225 ms | 406 ms | 742 ms |
| way 1 exact | 107 ms | 233 ms | 420 ms | 793 ms |

- At equal k, exact decay costs 5–12 % more proving time (extra gates, one more lookup).
- The duration does not matter: a 0 s and a 70 year old note prove equally fast.
- Per spent note, way 1 occupies 30 rows in the arithmetic columns and 59 range-check rows
  beside them. What counts for the full Circuit A is whether these rows push it to the next
  k — each step roughly doubles proving time.
- Proofs are ~5.5 KB because the range check uses eight byte limbs with a lookup each;
  a layout with fewer lookup arguments makes them smaller.
- Benchmark simplifications: note values are range-checked to 64 instead of 63 bits, and
  notes from before the decay start (`DECAY_START_TIME`) must store `max(t, T0)` as timestamp.

## The action circuit (`circuit/action_slice.rs`)

One shielded action, spend one note and create one, built from the Orchard gadgets:

* **note commitment** over the note of `crate::note` — Poseidon over field elements, not
  Sinsemilla over bits (see below)
* **Merkle path** of depth 32, Sinsemilla, as in Orchard
* **key**: `ivk = Poseidon(ak_x, nk, rivk)` — the `ak` of the spend authorisation, the `nk` of
  the nullifier and the `ivk` of the address are proven to be one key
* **nullifier** `Poseidon(nk, rho, cm)`
* **address**: `pk_d = [ivk] g_d`, a variable base multiplication; `g_d` and `pk_d` both go into
  the commitment
* **community**: public input, both notes belong to it and carry its coin
* **created note**: its value is the spent value decayed to `now`, its timestamp is the public
  `now`, and its `rho` is the nullifier just derived — all as the same cells, so nothing can
  drift apart
* **value commitment** `cv = [v] V + [rcv] R` and **spend authorisation** `rk = ak + [alpha] G`

### Why Poseidon for the commitment

Sinsemilla hashes a bit string, so every field of a note has to be decomposed and checked for
canonicity before it can be tied to the cells the rest of the circuit uses. That is what
orchard's 2000 line NoteCommit chip does. Poseidon takes field elements as they are: the cell
that carries the value into the decay gadget *is* the cell inside the commitment. A Poseidon
hash costs 42 rows per two absorbed elements, so the twelve element commitment is 252 rows —
the same order as the Sinsemilla version, without the canonicity machinery.

The tests in `action_slice.rs` attack this binding directly: another value or timestamp for the
decay, spending a known note with one's own key (`g_d := pk_d`), another `nk` for a second
nullifier, another `ak`, another community.

```sh
cargo run --release --example action_timing
```

| | k | rows used | prove | verify | proof |
|---|---|---|---|---|---|
| without decay | 11 | 2029 / 2048 | 387 ms | 4.7 ms | 4928 B |
| exact decay (unit.c bit chain) | 12 | 2054 / 4096 | 679 ms | 7.2 ms | 5440 B |
| windowed decay | 11 | 2034 / 2048 | 396 ms | 4.8 ms | 5408 B |

Measured after the security review (key derivation, `g_d` in the commitment, exact remainders).
The windowed chain still fits into k = 11, but with **14 rows to spare**; the bit chain no
longer does. The time lock of E8 and the expiry of E10 will need rows, so expect k = 12 (about
twice the proving time) once they are in, unless the layout gets tighter.

### What the windowed decay changes (`decay::decay_windowed`, `grdd_unit_calculate_decay_windowed`)

The 25 bits of the sub-year remainder are grouped into five 5-bit windows, one table lookup and
one multiplication per window instead of one per bit. The window factors come from the same
`DECAY_POWERS`, generated by `helper/precalculate_decay_windows.c` in the core and by
`decay::window_table` in Rust; both are checked against each other by the fourth column of
`test/decay_vectors.csv`, which the C function produces.

Fewer truncations mean it is not bit-identical to the bit chain: 89 of the 4252 vectors differ,
52 of them one unit higher, 37 one or two units lower, and **all of them above 10 billion GDD on
a single note**. Below that the two agree exactly. Against a 60-digit reference both stay
slightly under the exact `value * 2^(-duration/year)`; the windowed one is marginally closer.

## A shielded transfer (`bundle.rs`, `wire.rs`)

A bundle has `ACTIONS = 2` actions, each spending one note and creating one; what is missing
is filled with dummy notes of value 0, so every transfer looks the same from outside. All
actions share one proof. Each action publishes `cv_net = [decayed(v_old) - v_new] V + [rcv] R`,
and the binding signature under the sum of all `rcv` shows that they add up to zero — the
values balance across actions without any amount becoming visible.

The API follows the custody split of E5:

```text
server  build()        with the full viewing key: proof, encryption, rerandomisers
device  signer::sign() checks the transfer, then signs each real spend (see below)
server  authorize()    binding signature and the dummy spends
node    Ledger::apply  anchor known, nullifiers fresh, proof and signatures valid
```

```sh
cargo run --release --example bundle_timing
```

| | |
|---|---|
| keygen | 0.97 s, once per process |
| build and prove, 2 actions | 672 ms (16 threads) |
| decode and verify | 7 ms |
| wire size | 1714 B `ShieldedBundle` + 8137 B `ShieldedAuthorization` = 9.9 KB |

The proof for two actions is 7936 bytes. The design estimate in `privacy_todo.md` of about
5 KB per transaction assumed one action.

`tests_bundle.rs` walks through it: Alice pays Bob with change, Bob's wallet follows the tree
and spends his note to Carol 30 days later; a public creation is committed by the node through
the C ABI and spent by its owner. And the ways it must fail: double spend, unknown anchor,
unbalanced outputs, a swapped commitment or ciphertext, a spend signed by someone else, a
bundle decoded with another `created_at`.

**The wire bytes are checked against the C side:** `examples/wire_sample.rs` writes a bundle,
and the pbtools code generated from `shielded.proto` decodes all of it with the expected field
sizes. `test/bundle_smoke.c` runs the C ABI against those files:

```sh
cargo run --release --example wire_sample /tmp/sample
gcc -std=c11 -Iinclude test/bundle_smoke.c -o bundle_smoke target/release/libgradido_blockchain_zk.a -lpthread -ldl -lm
./bundle_smoke /tmp/sample
```

## Signing on the device (`signer.rs`)

The server builds and proves; the owner's device signs. A device that signed a 32-byte hash
from the server would sign whatever the server wants — a compromised server could swap the
payment to Bob for one to itself. So the device never takes a hash. The flow:

```text
server  build(.., Some(fvk.ovk), ..)             proof and ciphertexts, with the owner's ovk
server  body = TransactionBody { created_at, shielded_transfer: unauthorized.shielded_bytes() }
server  request = unauthorized.signing_request(body)       body + note openings + alphas
device  (review, sigs) = signer::sign(&request, &sk, community, rng)
device  shows review.payments / review.change, sends sigs only after the owner agrees
server  unauthorized.authorize(&body_sighash(&body), sigs, rng)
node    grdzk_bundle_verify(.., grdzk_body_sighash(body), ..)
```

`signer::review` recomputes the sighash from the body, accepts only a body that is a local
shielded transfer and nothing else, checks every created note against its commitment, its
ciphertexts and its memo, sorts the notes into payments and change, and signs only spends of
its own key. `SigningRequest::encode`/`decode` is the transport format. `tests_signer.rs` plays
the malicious server: swapped recipient, change to a foreign address, broken ciphertext, missing
ovk, wrong memo, alpha for a foreign spend, extra fields in the body, a signature reused for
another body.

The check is only worth something if the device's code does not come from the server it checks:
an app or a browser extension, not a page the community server delivers.

### The JavaScript interface (`wasm.rs`)

Only what the device does: keys, addresses, reviewing and signing a request. Proving stays on
the server, and the C ABI is left out of the WebAssembly build, so the module is 450 KB (149 KB
gzipped). Bytes are `Uint8Array`, amounts `BigInt`; TypeScript types come with the bindings.

```ts
generateSpendingKey(): Uint8Array                                     // 32 bytes
viewingKey(spendingKey): Uint8Array                                   // 128 bytes, for the server
address(spendingKey, diversifier, communityId): string                // "gdd1..."
creationAddress(spendingKey, year, month, communityId): string
decodeAddress(text): { raw, communityId }
reviewSigningRequest(spendingKey, community, communityId, request): Review
signSigningRequest(spendingKey, community, communityId, request): { review, signatures }
// Review = { createdAt, payments: [{ address, value, kind, memo, freeMemo }], change, spends, sighash }
```

Every check that fails throws an `Error` with the reason (`CommitmentMismatch(0)`, …). Storing
the spending key safely is the app's job; the module keeps no copy.

```sh
cargo build --release --target wasm32-unknown-unknown --lib
wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/gradido_blockchain_zk.wasm
```

The `wasm-bindgen` CLI must have exactly the version of the `wasm-bindgen` crate in `Cargo.lock`
(0.2.117, the last one that builds with rustc 1.85). `cargo install wasm-bindgen-cli --version
0.2.117` fails on 1.85 because of a newer `time` dependency; building it from the crate source
with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo generate-lockfile` first works.

The whole way through, with the device running as WebAssembly in Node.js:

```sh
wasm-bindgen --target nodejs --out-dir pkg-node target/wasm32-unknown-unknown/release/gradido_blockchain_zk.wasm
cargo run --release --example wasm_roundtrip pkg-node
```

and in a real browser, headless, served from a small HTTP server inside the example:

```sh
wasm-bindgen --target web --out-dir pkg-web target/wasm32-unknown-unknown/release/gradido_blockchain_zk.wasm
cargo run --release --example wasm_roundtrip -- --browser google-chrome pkg-web
cargo run --release --example wasm_roundtrip -- --browser firefox pkg-web
```

A Rust server builds a transfer with a memo; the device (`test/wasm_signer_checks.mjs`, the same
checks in `wasm_signer.mjs` for Node and `wasm_signer.html` for the browser) compares keys and
addresses with Rust, reviews the request, refuses one that pays Mallory while describing Bob, and
signs; the Rust ledger then accepts the transfer with those signatures. Passes in Node 18,
Chrome 148 and Firefox 140 ESR.

In a page the module needs no special headers (no threads, so no COOP/COEP), only to be served
over HTTP(S) rather than `file://`, ideally with `application/wasm`. A browser extension with
Manifest V3 has to allow `'wasm-unsafe-eval'` in its `content_security_policy`.

## Security review

A review of the circuit, the protocol layer and the C boundary found, and this version fixes:

| | what was wrong | fix |
|---|---|---|
| critical | the decay chip witnessed its own `value` and `t_note`, unconnected to the note: any note could be spent as a much larger, undecayed value | the chip copies the committed cells |
| critical | `ivk`, `nk`, `ak` and `g_d` were free witnesses: whoever knew a note (every sender, everybody for creations) could spend it with `g_d := pk_d, ivk := 1`, and the owner could nullify a note many times | `ivk = Poseidon(ak_x, nk, rivk)` in circuit, `g_d` in the commitment |
| critical | `community`/`coin_community` were free, so a dummy action could turn value into another coin | community is a public input, both notes carry its coin |
| high | the tree recomputed empty subtree roots on every call, ~46 ms per root | table of empty roots |
| high | the authorisation bytes were malleable: trailing proof bytes, unknown and repeated fields all verified; prost and pbtools read repeated sub-messages differently | fixed proof size, canonical encoding required, the ABI returns the proven anchor, nullifiers and commitments |
| medium | division remainders of the decay were checked to 70 bits instead of 64, letting a prover lower the result | exact 64 bit checks |
| medium | identical creations got identical notes, the second one unspendable; out-of-range fields gave notes no proof can open | `rho` from the tree position, ranges checked |
| low | value 64 instead of 63 bits, kind 4 instead of 1 bit, month aliasing in creation addresses, unchecked device signatures in `authorize`, identity points, missing `catch_unwind`, `Vec` capacity assumption in `grdzk_buffer_free`, a non-atomic `Ledger::apply` when the tree is full | fixed |

Not fixed, because they are design decisions or missing features rather than bugs:

* **Rounding and frequent transfers — decided to keep.** Decay per action rounds half up, as
  unit.c does. A note returns unchanged while `value * ln 2 * age / year < 0.5` units: 100 GDD
  re-sent every 20 s, or 1 GDD every 38 minutes, never decays. Accepted for unit.c compatibility.
* **E8 time lock and E10 expiry** are not in the circuit; `kind` and `expiry_epoch` are only
  committed. Cross community coins are not possible yet.
* The legacy skeleton ABI (`grdzk_prove`/`grdzk_verify`) proves nothing about notes; it is marked
  as such in the header.

## Threads, and proving in the browser

All numbers above use 16 threads. Proving one action (windowed decay, k = 11) scales like this
on this machine (Ryzen 7 5700G):

| threads | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| prove | 2.07 s | 1.06 s | 620 ms | 461 ms | 401 ms |

Near linear up to four cores. Keygen costs 2.95 s single threaded.

For a server the throughput matters more than the latency of one proof
(`cargo run --release --example throughput <concurrent> <proofs each>`):

| proofs at once | 1 | 4 | 8 | 16 |
|---|---|---|---|---|
| proofs/s | 2.5 | 3.9 | **4.2** | 3.6 |

So one 8-core desktop CPU does roughly **4 proofs/s**, about 350k per day. Note that only
shielded transfers need a proof at all — creations are public (E7) and cost the node nothing
but a hash. Do not run each proof single threaded to raise throughput: halo2 parallelises
internally through one global rayon pool, so `RAYON_NUM_THREADS=1` plus own threads serialises
everything (measured: 0.5 proofs/s).

**The crate compiles to `wasm32-unknown-unknown`.** The build exports only the signing device
interface (see below, 450 KB, 149 KB gzipped); proving in the browser would need its own exports:

```sh
cargo build --release --target wasm32-unknown-unknown --lib
```

Two things were needed for that, both in `Cargo.toml`: `getrandom` with the `js` feature, and
halo2 *without* `multicore` on wasm — rayon needs the atomics target feature, which a default
wasm build does not have.

What is still missing for client side proving:

1. ~~Precomputed fixed base tables~~ — done, `circuit/fixed_bases_generated.rs`.
2. **Web Workers for the cores.** `wasm-bindgen-rayon` gives halo2 its threads, but it needs a
   nightly toolchain with `-Z build-std` and `+atomics,+bulk-memory,+mutable-globals`, and the
   page must be cross-origin isolated (`COOP: same-origin`, `COEP: require-corp`). Without
   that it stays single threaded.
3. **The proving key.** halo2 0.3 can serialise `Params` but not `ProvingKey`, so the browser
   has to run keygen itself on every start (~3 s native single threaded, more in wasm). Either
   keep it alive in a worker, or move to a halo2 version that can serialise it.
4. **Run it in a worker anyway**, so the page does not freeze for seconds.

Rule of thumb for the estimate: wasm is 2-3x slower than native, so one action is roughly 4-6 s
single threaded and 1.5-2.5 s with four workers on a desktop; a phone is slower again. Under
E5 only self-custody users need this at all — for custodial accounts the community server
proves and the device only signs 32 bytes.

## Build

```sh
cargo build --release      # produces target/release/libgradido_blockchain_zk.{a,so}
cargo test --release       # 105 tests, about 15 s; debug builds are much slower
cargo test --release -- --ignored   # all 4252 unit.c vectors through both chains
cargo run --release --example timing
```

## C ABI

Header: [`include/gradido_blockchain_zk.h`](include/gradido_blockchain_zk.h). Field elements cross the boundary as
32-byte little-endian, matching `Fp::to_repr`.

```c
#include "gradido_blockchain_zk.h"

grdzk_init();                       /* optional: pay keygen up front */

grdzk_buffer proof = {0};
int32_t rc = grdzk_prove(inputs, GRDZK_N_IN, outputs, GRDZK_N_OUT, sighash, &proof);
if (rc == GRDZK_OK) {
    rc = grdzk_verify(proof.data, proof.len, sighash);
    grdzk_buffer_free(&proof);
}
```

That is the skeleton. For the node the ABI has what a shielded transfer needs:

```c
grdzk_bundle_init();                /* keygen, ~1 s */

/* sighash = hash of body_bytes, community = 32 byte field element, now = created_at */
uint8_t effects[GRDZK_BUNDLE_EFFECTS_SIZE];   /* anchor | nf_0 | cm_0 | nf_1 | cm_1 */
int32_t rc = grdzk_bundle_verify(shielded, shielded_len, auth, auth_len,
                                 community, created_at, sighash, effects);
/* GRDZK_OK, or GRDZK_ERR_WIRE / _PROOF / _SPEND_AUTH / _BINDING */

GrdzkTree *tree = grdzk_tree_new();
grdzk_tree_size(tree, &position);         /* position of the next note */
grdzk_tree_append(tree, cm);              /* per created note, in chain order */
grdzk_tree_checkpoint(tree);              /* per confirmed transaction */
grdzk_tree_root(tree, root);              /* note_commitment_tree_root */
grdzk_tree_free(tree);

/* public creation: the node computes the commitment itself, rho comes from the position */
grdzk_creation_commitment(community, amount, created_at, expiry, address43,
                          position, rseed, memo_cm, cm);
```

`grdzk_bundle_verify` checks the proof and both signatures. Whether the anchor is known and the
nullifiers are fresh is the node's state and therefore its job (`Ledger::verify` in Rust shows
the order). The node takes anchor, nullifiers and commitments from `effects`, not from its own
protobuf parser: only the canonical encoding is accepted, but reading the proven values back is
the simpler guarantee.

All entry points catch Rust panics and return an error code rather than unwinding across
the boundary. Error codes are the `GRDZK_ERR_*` constants in the header.

### Smoke test

```sh
cargo build --release
gcc -std=c11 -Iinclude test/smoke.c -o smoke target/release/libgradido_blockchain_zk.a -lpthread -ldl -lm
./smoke
```

and for the bundle ABI `test/bundle_smoke.c`, see above.

### CMake integration

`CMakeLists.txt` here uses the `cargo_build` macro of `gradido_blockchain` (the one
`iota_rust_clib` uses). Add this repository as a submodule and wire it in next to it:

```sh
git submodule add git@github.com:gradido/gradido-blockchain-zk.git dependencies/gradido-blockchain-zk
```

```cmake
add_subdirectory(dependencies/gradido-blockchain-zk)
include_directories("dependencies/gradido-blockchain-zk/include")
target_link_libraries(${PROJECT_NAME} ... gradido_blockchain_zk)
```

Only projects that consume it need a Rust toolchain.

### Decay test vectors

`test/decay_vectors.csv` comes from the C implementation in `gradido-blockchain-core`; see
`test/gen_decay_vectors.c` for how to regenerate it. The CI regenerates it from the core's master
branch and fails when the two differ, so the circuit cannot drift away from `unit.c`.

## Notes for whoever picks this up

- **halo2 does not validate your witness.** `create_proof` never checks that the gates are
  satisfied; it emits a proof that simply fails to verify. `MockProver` is what checks
  satisfaction, and it is a test-only tool. `prover::check_witness` therefore validates the
  preconditions explicitly before proving. For a larger circuit, run `MockProver` behind
  `debug_assertions` instead of hand-writing the checks.
- **Do not pass `default-features = false` to halo2_proofs** for native builds. It silently
  drops `multicore` and proving gets ~5x slower. `Cargo.toml` does it only for wasm32.
- **Soundness of the balance check.** Values are range-checked below `2^160`, so a sum of
  two stays below `2^161`, far under the Pallas modulus (~2^254). Field equality therefore
  implies integer equality — no wraparound, no forging money via a "negative" value. If
  `N_IN`/`VALUE_BITS` grow, re-check that argument.
- **`without_witnesses` must keep the same shape** as the populated circuit, or keygen and
  proving diverge in ways that are painful to debug.
- The skeleton's values are `2^160` because an anchored value needs 64 bit gddCent + 63
  doublings + ~32 fractional bits (the dropped E2). Notes in the action circuit hold a plain
  63 bit value (non-negative int64).
