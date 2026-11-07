"""
Check that the Rust Tier-2 scorer matches the PyTorch model on every dataset row.

Runs the native build (src/bin/batch.rs) and, when it has been built and Node is
on PATH, the Worker's WASM build (worker/parity.mjs). Exits 1 on any mismatch.

Run from the repo root:  python tier2_scorer/parity_check.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import server  # noqa: E402  (PyTorch reference: same model and threshold the API serves)

MANIFEST = os.path.join(ROOT, "tier2_scorer", "Cargo.toml")
WASM = os.path.join(ROOT, "tier2_scorer", "target", "wasm32-unknown-unknown", "release", "tier2_scorer.wasm")
TOL = 1e-5


def compare(name, got, ref, threshold):
    diff = float(np.abs(got - ref).max())
    flips = int(((got >= threshold) != (ref >= threshold)).sum())
    ok = diff <= TOL and flips == 0
    print(f"  {name:<6} max |diff| = {diff:.2e}  verdict flips = {flips}  {'OK' if ok else 'FAIL'}")
    return ok


def main():
    feat = np.load(os.path.join(ROOT, "dataset", "behavioral_dataset.npz"))["feat"].astype("<f4")
    model, threshold = server.load_model_and_threshold()
    with torch.no_grad():
        ref = torch.sigmoid(model(torch.from_numpy(feat))).squeeze(1).numpy()

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "features.bin")
        feat.tofile(path)
        with open(path, "rb") as f:
            native = subprocess.run(
                ["cargo", "run", "--release", "--quiet", "--manifest-path", MANIFEST, "--bin", "batch"],
                stdin=f, capture_output=True, check=True)
        print(f"{len(feat)} rows  ({native.stderr.decode().strip()})")
        ok = compare("native", np.frombuffer(native.stdout, "<f4"), ref, threshold)

        if os.path.exists(WASM) and shutil.which("node"):
            wasm = subprocess.run(["node", os.path.join(ROOT, "worker", "parity.mjs"), WASM, path],
                                  capture_output=True, check=True)
            ok &= compare("wasm", np.frombuffer(wasm.stdout, "<f4"), ref, threshold)
        else:
            print("  wasm   skipped (build it with: cargo build --release --lib --target wasm32-unknown-unknown)")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
