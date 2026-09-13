// The signing device's checks, shared by Node.js (wasm_signer.mjs) and the browser
// (wasm_signer.html). `zk` is the wasm-bindgen module, `io` reads the files the Rust side wrote.
// Returns the signatures, concatenated.

function assert(condition, what) {
  if (!condition) throw new Error(`check failed: ${what}`);
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function throws(fn, pattern, what) {
  try {
    fn();
  } catch (e) {
    assert(pattern.test(String(e.message ?? e)), `${what}: unexpected error "${e.message ?? e}"`);
    return;
  }
  throw new Error(`check failed: ${what} did not throw`);
}

export async function runChecks(zk, io) {
  const sk = await io.read("spending_key.bin");
  const community = await io.read("community.bin");
  const communityId = await io.read("community_id.bin");
  const request = await io.read("request.bin");
  let checks = 0;
  const check = async (what, fn) => {
    await fn();
    checks++;
    io.log(`  ok  ${what}`);
  };

  await check("keys and addresses agree with Rust", async () => {
    assert(equalBytes(zk.viewingKey(sk), await io.read("viewing_key.bin")), "viewing key");
    const own = zk.address(sk, new Uint8Array(11).fill(2), communityId);
    assert(own === (await io.text("own_address.txt")), "own address");
    const decoded = zk.decodeAddress(own);
    assert(equalBytes(decoded.communityId, communityId) && decoded.raw.length === 43, "decoded address");
    const typo = own.slice(0, -1) + (own.endsWith("q") ? "p" : "q");
    throws(() => zk.decodeAddress(typo), /invalid address/, "address with a typo");
    assert(/^gdd1/.test(zk.creationAddress(sk, 2026, 3, communityId)), "creation address");
    throws(() => zk.creationAddress(sk, 2026, 13, communityId), /month/, "month 13");
  });

  await check("generated keys are 32 random bytes", () => {
    const a = zk.generateSpendingKey();
    const b = zk.generateSpendingKey();
    assert(a.length === 32 && !equalBytes(a, b), "two random keys");
  });

  await check("the review shows Bob, the amount, the memo and the change", async () => {
    const review = zk.reviewSigningRequest(sk, community, communityId, request);
    assert(review.payments.length === 1, "one payment");
    const payment = review.payments[0];
    assert(payment.address === (await io.text("bob_address.txt")), "recipient");
    assert(payment.value === 3000000n, "amount");
    assert(payment.kind === "normal", "kind");
    assert(new TextDecoder().decode(payment.memo) === "Danke fuer die Gartenarbeit", "memo");
    assert(review.change === BigInt(await io.text("change.txt")), "change");
    assert(review.spends === 1, "spends");
    assert(equalBytes(review.sighash, await io.read("sighash.bin")), "sighash");
  });

  await check("a request that pays someone else than it claims is refused", async () => {
    const evil = await io.read("evil_request.bin");
    throws(() => zk.reviewSigningRequest(sk, community, communityId, evil), /CommitmentMismatch/, "review");
    throws(() => zk.signSigningRequest(sk, community, communityId, evil), /CommitmentMismatch/, "sign");
  });

  await check("broken input is refused with a reason", () => {
    throws(() => zk.reviewSigningRequest(sk.slice(1), community, communityId, request), /spending key must be 32 bytes/, "short key");
    throws(() => zk.reviewSigningRequest(sk, community, communityId, request.slice(1)), /Request/, "cut request");
    throws(() => zk.signSigningRequest(zk.generateSpendingKey(), community, communityId, request), /Mismatch|Spend/, "foreign key");
  });

  let signatures;
  await check("signing returns one 64-byte signature per own spend", () => {
    const signed = zk.signSigningRequest(sk, community, communityId, request);
    assert(signed.review.payments[0].value === 3000000n, "review with the signatures");
    assert(signed.signatures.length === 1 && signed.signatures[0].length === 64, "one signature");
    signatures = new Uint8Array(signed.signatures.flatMap((s) => [...s]));
  });

  io.log(`all ${checks} checks passed`);
  return signatures;
}
