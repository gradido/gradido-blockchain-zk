// The device in Node.js: `node test/wasm_signer.mjs <wasm-bindgen --target nodejs dir> <data dir>`
// (started by `cargo run --release --example wasm_roundtrip`).
import { createRequire } from "module";
import fs from "fs";
import path from "path";
import { runChecks } from "./wasm_signer_checks.mjs";

const [pkg, dir] = process.argv.slice(2);
const zk = createRequire(import.meta.url)(path.resolve(pkg, "gradido_blockchain_zk.js"));
const io = {
  read: async (name) => new Uint8Array(fs.readFileSync(path.join(dir, name))),
  text: async (name) => fs.readFileSync(path.join(dir, name), "utf8"),
  log: (line) => console.log(line),
};
const signatures = await runChecks(zk, io);
fs.writeFileSync(path.join(dir, "signatures.bin"), signatures);
