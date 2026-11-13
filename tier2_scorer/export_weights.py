"""
Export tier2_behavioral.pt to tier2_scorer/weights.bin for the Rust scorer.

BatchNorm layers are folded into the Linear layer before them (eval mode, so
dropout is a no-op). Layout, all little-endian f32:
  threshold, then for each dense layer in order (proj, res1.a, res1.b,
  res2.a, res2.b, head): weight [out x in] row-major, bias [out].

Run from the repo root:  python tier2_scorer/export_weights.py
"""
import json
import os

import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EPS = 1e-5  # nn.BatchNorm1d default, as used in server.py / train_tier2_behavioral.py


def fold(sd, lin, bn):
    w, b = sd[f"{lin}.weight"].double(), sd[f"{lin}.bias"].double()
    scale = sd[f"{bn}.weight"].double() / torch.sqrt(sd[f"{bn}.running_var"].double() + EPS)
    return w * scale[:, None], (b - sd[f"{bn}.running_mean"].double()) * scale + sd[f"{bn}.bias"].double()


def main():
    sd = torch.load(os.path.join(ROOT, "tier2_behavioral.pt"), map_location="cpu")
    with open(os.path.join(ROOT, "tier2_behavioral_threshold.json"), encoding="utf-8") as f:
        threshold = json.load(f)["threshold"]

    layers = [fold(sd, "proj.0", "proj.1")]
    for r in ("res1", "res2"):
        layers += [fold(sd, f"{r}.block.0", f"{r}.block.1"), fold(sd, f"{r}.block.4", f"{r}.block.5")]
    layers.append((sd["head.weight"].double(), sd["head.bias"].double()))

    parts = [np.array([threshold], dtype="<f4")]
    for w, b in layers:
        parts += [w.numpy().astype("<f4").ravel(), b.numpy().astype("<f4")]
    blob = np.concatenate(parts)
    out = os.path.join(ROOT, "tier2_scorer", "weights.bin")
    blob.tofile(out)
    print(f"wrote {out}: {blob.size} floats, threshold={threshold:.6f}")


if __name__ == "__main__":
    main()
