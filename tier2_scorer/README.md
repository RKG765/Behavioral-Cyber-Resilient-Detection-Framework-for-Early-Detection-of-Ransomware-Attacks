# tier2_scorer: the Tier-2 model in Rust

One crate, two scorers (plan: `docs/PROD_ARCHITECTURE.md`, build step 1):

- **AWS Lambda** (native): `src/bin/lambda.rs`, built with `--features lambda`
- **Cloudflare Worker** (WASM): `../worker/src/index.js` loads the crate built for `wasm32-unknown-unknown`

Both serve `POST /v1/score` with `{"features": [99 numbers]}` and return
`{"verdict": "KILL" | "BENIGN", "request_id": "..."}`. There's no auth yet; that's build step 2.

## Weights

`weights.bin` is generated from `tier2_behavioral.pt`, with BatchNorm folded into the dense layers,
plus the threshold. Re-run this after retraining:

```bash
python tier2_scorer/export_weights.py
```

## Check

```bash
cargo test --release --features lambda --manifest-path tier2_scorer/Cargo.toml
cargo build --release --lib --target wasm32-unknown-unknown --manifest-path tier2_scorer/Cargo.toml
python tier2_scorer/parity_check.py
```

`parity_check.py` compares the native and WASM builds with PyTorch on all 1,470 dataset rows.
Last run: max |diff| 6.3e-7, no verdict flips, about 9-11 µs per score natively.

## Deploy (needs your accounts; not run yet)

- **Lambda (arm64):** install `cargo-lambda`, then
  `cargo lambda build --release --arm64 --features lambda --bin lambda`.
  Deploy the `bootstrap` zip as a `provided.al2023` function with a Function URL, fronted by
  CloudFront (plan section 3.2).
- **Worker:** `cd worker && npx wrangler dev` to try it locally, then `npx wrangler deploy`.
  Wrangler runs the WASM build itself (see `wrangler.toml`).
