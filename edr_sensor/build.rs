// Release settings for lib.rs `release_config()`: packaging/build.ps1 sets these; dev builds get "".
fn main() {
    for key in ["HALTLINE_ENDPOINTS", "HALTLINE_SERVER_PUBKEY", "HALTLINE_UPDATE_URL", "HALTLINE_UPDATE_PUBKEY"] {
        println!("cargo:rerun-if-env-changed={key}");
        println!("cargo:rustc-env={key}={}", std::env::var(key).unwrap_or_default());
    }
}
