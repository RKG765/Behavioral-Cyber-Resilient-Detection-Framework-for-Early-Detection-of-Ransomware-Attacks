//! Tier-2 behavioral scorer: the residual MLP from `server.py`, with each
//! BatchNorm folded into the dense layer before it (`export_weights.py`).
//! One crate builds both scorers: AWS Lambda (native) and the Cloudflare
//! Worker (wasm32, through the `input_ptr` / `score` / `threshold` exports).

use std::sync::OnceLock;

#[cfg(feature = "lambda")]
pub mod admin;
#[cfg(feature = "lambda")]
pub mod auth;

pub const FEATURE_DIM: usize = 99;
const HIDDEN: usize = 64;
/// (out, in) of each dense layer: proj, res1.a, res1.b, res2.a, res2.b, head.
const SHAPES: [(usize, usize); 6] = [
    (HIDDEN, FEATURE_DIM),
    (HIDDEN, HIDDEN),
    (HIDDEN, HIDDEN),
    (HIDDEN, HIDDEN),
    (HIDDEN, HIDDEN),
    (1, HIDDEN),
];
static BLOB: &[u8] = include_bytes!("../weights.bin");

struct Dense {
    w: Vec<f32>,
    b: Vec<f32>,
}

struct Model {
    threshold: f32,
    layers: Vec<Dense>,
}

fn model() -> &'static Model {
    static M: OnceLock<Model> = OnceLock::new();
    M.get_or_init(|| {
        let f: Vec<f32> = BLOB.chunks_exact(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
        let expected = 1 + SHAPES.iter().map(|(o, i)| o * i + o).sum::<usize>();
        assert_eq!(f.len(), expected, "weights.bin does not match the Tier-2 architecture");
        let mut at = 1;
        let layers = SHAPES
            .iter()
            .map(|&(o, i)| {
                let w = f[at..at + o * i].to_vec();
                at += o * i;
                let b = f[at..at + o].to_vec();
                at += o;
                Dense { w, b }
            })
            .collect();
        Model { threshold: f[0], layers }
    })
}

fn dense(d: &Dense, x: &[f32], relu: bool) -> Vec<f32> {
    d.w.chunks_exact(x.len())
        .zip(&d.b)
        .map(|(row, b)| {
            let v = b + row.iter().zip(x).map(|(w, x)| w * x).sum::<f32>();
            if relu { v.max(0.0) } else { v }
        })
        .collect()
}

/// Tier-2 malware probability in [0, 1].
pub fn score(x: &[f32; FEATURE_DIM]) -> f32 {
    let l = &model().layers;
    let mut h = dense(&l[0], x, true);
    for blk in [&l[1..3], &l[3..5]] {
        let t = dense(&blk[1], &dense(&blk[0], &h, true), false);
        h = h.iter().zip(&t).map(|(a, b)| (a + b).max(0.0)).collect();
    }
    1.0 / (1.0 + (-dense(&l[5], &h, false)[0]).exp())
}

pub fn threshold() -> f32 {
    model().threshold
}

/// Same rule as server.py: KILL when the probability reaches the threshold.
pub fn verdict(p: f32) -> &'static str {
    if p >= threshold() { "KILL" } else { "BENIGN" }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::FEATURE_DIM;

    static mut INPUT: [f32; FEATURE_DIM] = [0.0; FEATURE_DIM];

    /// The Worker writes the 99 features here, then calls `score`.
    #[no_mangle]
    pub extern "C" fn input_ptr() -> *mut f32 {
        core::ptr::addr_of_mut!(INPUT) as *mut f32
    }

    #[no_mangle]
    pub extern "C" fn score() -> f32 {
        super::score(unsafe { &*core::ptr::addr_of!(INPUT) })
    }

    #[no_mangle]
    pub extern "C" fn threshold() -> f32 {
        super::threshold()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_load_and_score_is_a_probability() {
        let p = score(&[0.0; FEATURE_DIM]);
        assert!((0.0..=1.0).contains(&p));
        assert!((threshold() - 0.6546).abs() < 1e-3);
        assert_eq!(verdict(threshold()), "KILL");
        assert_eq!(verdict(threshold() - 1e-4), "BENIGN");
    }
}
