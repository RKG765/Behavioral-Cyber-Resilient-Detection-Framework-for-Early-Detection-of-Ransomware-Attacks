# edr_sensor — Rust Sysmon feature extractor

Python extension (Rust + PyO3) that replaces the agent's simulated
`np.random.rand(1, 99)` features with **real behavioral features from live Sysmon telemetry**.

```
Sysmon event log ──EvtSubscribe (push, OS thread pool)──▶ Rust: render XML → parse
      → per-process buffer (earliest 50 events + EventID-1 row, keyed by ProcessGuid)
      → 99 features, same as build_behavioral_dataset.py
agent.py ── sensor.features(pid) ──▶ list[float] (99) | None  ──▶ ONNX Tier 1
```

## Build & install

Needs the Rust toolchain (MSVC) and maturin (`pip install maturin`).

```bash
cd edr_sensor
python -m maturin build --release -o dist
pip install dist/edr_sensor-0.1.0-cp38-abi3-win_amd64.whl
```

For iterative development, `python -m maturin develop --release` installs into the active venv.

Rust unit tests: `cargo test`.

## Runtime requirements

- **Sysmon installed** (`Microsoft-Windows-Sysmon/Operational` channel). Without it
  `Sensor.start()` raises `OSError` 15007 and `agent.py` falls back to the simulated
  extractor (kills stay dry-run, #23).
- Admin rights (or Event Log Readers membership) to read the channel. The agent already
  requires admin.
- The Sysmon config must log the event types the features use: 1, 3, 7, 10, 11, 12–14, 22.

## Python API

| Call | Purpose |
|---|---|
| `Sensor(channel=DEFAULT_CHANNEL, max_processes=8192)` | Create sensor; buffers are bounded (LRU eviction) |
| `.start()` / `.stop()` / `.running` | Subscribe / unsubscribe |
| `.features(pid, min_events=3)` | 99-float vector, or `None` while fewer than 3 events |
| `.event_count(pid)`, `.forget(pid)` | Inspect / free one process's buffer |
| `.ingest_xml(xml)` | Feed a rendered event (tests, replaying exported logs) |
| `.stats()` | received / ingested / errors / evicted / tracked |
| `compute_features(events)` | Pure function over dicts with dataset column names |
| `feature_names()`, `FEATURE_DIM`, `WINDOW` | Schema |

## Training parity

`features.rs` is a line-by-line port of `build_behavioral_dataset.py`. To verify it,
`parity_check.py` re-reads each training process's raw rows from the LMD-2023 CSV, runs them
through the Rust code, and compares against `dataset/behavioral_dataset.npz`:

```bash
python edr_sensor/parity_check.py
```

Last run: **1470/1470 processes identical, max |diff| = 0.0**.

If you change a feature, change it in both places and re-run the check.

## Known behavior differences from training

- Events are attributed by `ProcessGuid`, as in training. Sysmon EventIDs 8 and 10 carry only
  `SourceProcessGuid`, so they're ignored (they had no owner in the training CSV either).
- Training used each process's first 50 events. The agent scores every 2 s during a
  30 s window, so early scores see a partial window (`win_len_frac` < 1).
