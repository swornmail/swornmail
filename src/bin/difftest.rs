//! Differential-test evaluator: reads a corpus on stdin and prints this
//! implementation's verification result per case, for cross-checking against
//! the Go reference (gate B). Not part of the published crate's purpose; it
//! exists so an external harness can drive the Rust verifier over a large
//! mutated-token corpus.
//!
//! Input (tab-separated, one case per line; first line is the shared public
//! key in hex):
//!
//! ```text
//! <pubkey_hex>
//! <name>\t<token_hex>\t<source_ip>\t<now_unix>
//! ...
//! ```
//!
//! Output: `<name>\t<reason>\t<operator>\t<unit>` per case.

use std::io::{self, BufRead, Write};
use std::net::Ipv6Addr;

use swornmail::{reason_str, verify, Ed25519PublicKey};

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hex_val(b[i])? << 4) | hex_val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn main() {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let pub_hex = lines
        .next()
        .expect("first line must be the public key")
        .expect("read public key line");
    let pk_bytes = hex_decode(pub_hex.trim()).expect("public key is hex");
    let key = Ed25519PublicKey::from_bytes(&pk_bytes).expect("valid Ed25519 key");

    let stdout = io::stdout();
    let mut w = stdout.lock();
    for line in lines {
        let line = line.expect("read case line");
        if line.is_empty() {
            continue;
        }
        let mut it = line.splitn(4, '\t');
        let name = it.next().unwrap_or("");
        let token_hex = it.next().unwrap_or("");
        let source_str = it.next().unwrap_or("");
        let now: i64 = it.next().unwrap_or("0").parse().unwrap_or(0);

        let token = match hex_decode(token_hex) {
            Some(t) => t,
            None => {
                writeln!(w, "{name}\tmalformed\t\t").expect("write");
                continue;
            }
        };
        let source: Ipv6Addr = match source_str.parse() {
            Ok(s) => s,
            Err(_) => {
                writeln!(w, "{name}\tbad_source\t\t").expect("write");
                continue;
            }
        };

        let outcome = verify(&token, &key, source, now);
        let reason = reason_str(&outcome);
        let (operator, unit) = match &outcome {
            Ok(v) => (v.operator.clone(), v.unit.to_string()),
            Err(_) => (String::new(), String::new()),
        };
        writeln!(w, "{name}\t{reason}\t{operator}\t{unit}").expect("write");
    }
}
