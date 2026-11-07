//! Scores raw little-endian f32 rows of 99 features from stdin and writes one
//! f32 probability per row to stdout. Used by parity_check.py; prints timing to stderr.

use std::io::{Read, Write};
use tier2_scorer::{score, FEATURE_DIM};

fn main() {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).expect("read stdin");
    assert!(!buf.is_empty() && buf.len() % (4 * FEATURE_DIM) == 0, "stdin must be rows of {FEATURE_DIM} f32");
    let rows: Vec<[f32; FEATURE_DIM]> = buf
        .chunks_exact(4 * FEATURE_DIM)
        .map(|r| std::array::from_fn(|i| f32::from_le_bytes(r[4 * i..4 * i + 4].try_into().unwrap())))
        .collect();
    score(&rows[0]); // load the weights before timing
    let t = std::time::Instant::now();
    let out: Vec<u8> = rows.iter().flat_map(|r| score(r).to_le_bytes()).collect();
    eprintln!("{} rows, {:.2} us per score", rows.len(), t.elapsed().as_secs_f64() * 1e6 / rows.len() as f64);
    std::io::stdout().write_all(&out).expect("write stdout");
}
