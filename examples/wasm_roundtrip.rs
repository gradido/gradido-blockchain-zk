//! End to end through the WebAssembly interface: a Rust "server" builds a transfer and a signing
//! request, the device runs as WebAssembly, and its signatures are checked in the Rust ledger.
//!
//! In Node.js (`test/wasm_signer.mjs`):
//! `cargo run --release --example wasm_roundtrip <wasm-bindgen --target nodejs dir>`
//!
//! In a real browser, headless (`test/wasm_signer.html`), served from a local HTTP server:
//! `cargo run --release --example wasm_roundtrip --browser <chrome|firefox> <wasm-bindgen --target web dir>`
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng};

use gradido_blockchain_zk::bundle::{body_sighash, build, Ledger, OutputInfo, SpendInfo};
use gradido_blockchain_zk::keys::SpendingKey;
use gradido_blockchain_zk::note::{from_parts, NoteKind, RandomSeed};
use gradido_blockchain_zk::note_encryption::NoteWithSeed;
use gradido_blockchain_zk::signer::{MemoOpening, SigningRequest};
use gradido_blockchain_zk::tree::CommitmentTree;
use gradido_blockchain_zk::{address, decay, memo, wire};

type Base = pallas::Base;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (browser, pkg) = match args.as_slice() {
        [pkg] => (None, pkg.clone()),
        [flag, browser, pkg] if flag == "--browser" => (Some(browser.clone()), pkg.clone()),
        _ => panic!("usage: wasm_roundtrip [--browser <chrome|firefox binary>] <wasm-bindgen output dir>"),
    };
    let dir = std::env::temp_dir().join(format!("gradido_blockchain_zk_wasm_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, data: &[u8]| std::fs::write(dir.join(name), data).unwrap();

    let mut rng = StdRng::seed_from_u64(1);
    let community = Base::from(7);
    let community_id = [0x42u8; 16];
    let now = 1_800_000_000u64;
    let alice = SpendingKey::from_bytes([1u8; 32]);
    let fvk = alice.full_viewing_key();
    let bob = SpendingKey::from_bytes([2u8; 32]).full_viewing_key().address([1u8; 11]);
    let mallory = SpendingKey::from_bytes([66u8; 32]).full_viewing_key().address([6u8; 11]);

    // Alice's note and the ledger
    let rseed = RandomSeed::random(&mut rng);
    let note = from_parts(community, community, 1_000_0000, now - 100 * 86_400, NoteKind::Normal, 0,
        &fvk.address([9u8; 11]), Base::random(&mut rng), Base::zero(), rseed).unwrap();
    let mut ledger = Ledger::new();
    ledger.add_note(note.commitment()).unwrap();
    let mut tree = CommitmentTree::default();
    let position = tree.append(note.commitment(), true).unwrap();
    tree.checkpoint();
    let spend = SpendInfo { fvk, note: NoteWithSeed { note, rseed }, position: u64::from(position) as u32,
        path: tree.witness(position).unwrap() };
    let spendable = decay::decay_windowed(1_000_0000, 100 * 86_400);

    // the server: 300 GDD to Bob with a memo, the rest back to Alice
    let outputs = |to: gradido_blockchain_zk::keys::Address| {
        let text = memo::pad(b"Danke fuer die Gartenarbeit").unwrap();
        let r_memo = Base::from(77);
        let mut payment = OutputInfo::new(to, 300_0000);
        payment.memo_cm = memo::commit(&text, r_memo);
        payment.memo_opening = Some(MemoOpening { text, r_memo });
        vec![payment, OutputInfo::new(fvk.address([2u8; 11]), spendable - 300_0000)]
    };
    let build_request = |to, rng: &mut StdRng| {
        let unauthorized = build(community, ledger.tree.root(), now, vec![spend.clone()], outputs(to), Some(fvk.ovk), rng)
            .expect("build");
        let body = wire::encode_transfer_body(now, 4, &unauthorized.shielded_bytes());
        let request = unauthorized.signing_request(body);
        (unauthorized, request)
    };
    let (unauthorized, request) = build_request(bob, &mut rng);
    // a lying server: the body pays Mallory, the openings describe the payment to Bob
    let (_, to_mallory) = build_request(mallory, &mut rng);
    let evil = SigningRequest { body: to_mallory.body, ..request.clone() };

    write("spending_key.bin", &alice.to_bytes());
    write("viewing_key.bin", &fvk.to_bytes());
    write("community.bin", &community.to_repr());
    write("community_id.bin", &community_id);
    write("own_address.txt", address::encode(&fvk.address([2u8; 11]), &community_id).as_bytes());
    write("bob_address.txt", address::encode(&bob, &community_id).as_bytes());
    write("change.txt", (spendable - 300_0000).to_string().as_bytes());
    write("request.bin", &request.encode());
    write("evil_request.bin", &evil.encode());
    write("sighash.bin", &body_sighash(&request.body));

    // the device
    let raw = match browser {
        None => {
            let status = Command::new("node")
                .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/test/wasm_signer.mjs"))
                .arg(&pkg)
                .arg(&dir)
                .status()
                .expect("node");
            assert!(status.success(), "the device script failed");
            std::fs::read(dir.join("signatures.bin")).unwrap()
        }
        Some(browser) => run_in_browser(&browser, Path::new(&pkg), &dir),
    };

    // back on the server: the device's signatures complete the transfer
    let signatures = raw
        .chunks(64)
        .map(|c| reddsa::Signature::from(<[u8; 64]>::try_from(c).unwrap()))
        .collect();
    let sighash = body_sighash(&request.body);
    let bundle = unauthorized.authorize(&sighash, signatures, &mut rng).expect("device signatures are valid");
    ledger.apply(&bundle, &sighash).expect("the ledger accepts the transfer");
    println!("ledger accepted the transfer signed in WebAssembly");
    std::fs::remove_dir_all(&dir).ok();
}

/// Serves page, bindings and request on localhost, opens the page in a headless browser and
/// waits until the page posts its signatures back.
fn run_in_browser(browser: &str, pkg: &Path, data: &Path) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/test/wasm_signer.html", listener.local_addr().unwrap());
    let profile = data.join("browser-profile");
    std::fs::create_dir_all(&profile).unwrap();
    let mut command = Command::new(browser);
    if browser.contains("firefox") {
        command.args(["--headless", "--no-remote", "--profile"]).arg(&profile).arg(&url);
    } else {
        command.args(["--headless=new", "--disable-gpu", "--no-first-run"]).arg(format!("--user-data-dir={}", profile.display())).arg(&url);
    }
    let mut child = command.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("browser");

    let test_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/test"));
    let deadline = Instant::now() + Duration::from_secs(120);
    listener.set_nonblocking(true).unwrap();
    let result = loop {
        assert!(Instant::now() < deadline, "the browser did not report back in time");
        let Ok((mut stream, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        stream.set_nonblocking(false).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header.trim().is_empty() {
                break;
            }
            if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        let mut parts = request_line.split_whitespace();
        let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

        if method == "POST" {
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").unwrap();
            match target {
                "/log" => println!("{}", String::from_utf8_lossy(&body)),
                "/signatures" => break Ok(body),
                _ => break Err(String::from_utf8_lossy(&body).into_owned()),
            }
            continue;
        }
        let file = match target.split_once('/').map(|(_, rest)| rest).and_then(|rest| rest.split_once('/')) {
            Some(("pkg", name)) => pkg.join(name),
            Some(("test", name)) => test_dir.join(name),
            Some(("data", name)) => data.join(name),
            _ => PathBuf::new(),
        };
        match std::fs::read(&file) {
            Ok(content) if !target.contains("..") => {
                let mime = match file.extension().and_then(|e| e.to_str()) {
                    Some("wasm") => "application/wasm",
                    Some("js") | Some("mjs") => "text/javascript",
                    Some("html") => "text/html; charset=utf-8",
                    _ => "application/octet-stream",
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    content.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&content).unwrap();
            }
            _ => stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap(),
        }
    };
    child.kill().ok();
    child.wait().ok();
    match result {
        Ok(signatures) => signatures,
        Err(error) => panic!("the device failed in the browser:\n{error}"),
    }
}
