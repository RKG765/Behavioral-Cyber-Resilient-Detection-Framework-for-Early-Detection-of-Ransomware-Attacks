//! Device identity for signed Tier-2 requests (plan section 4.1).
//!
//! A non-exportable ECDSA P-256 key in the TPM (Microsoft Platform Crypto Provider),
//! or a Software KSP key on PCs without one. Signatures are raw r||s over SHA-256,
//! the format WebCrypto (Worker) and the `p256` crate (Lambda) verify.

use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
};

const TPM_PROVIDER: &str = "Microsoft Platform Crypto Provider";
const SOFTWARE_PROVIDER: &str = "Microsoft Software Key Storage Provider";
const MACHINE_KEY: u32 = 0x20; // NCRYPT_MACHINE_KEY_FLAG
const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(hr: i32, what: &str) -> Result<(), String> {
    if hr == 0 { Ok(()) } else { Err(format!("{what} failed: 0x{:08X}", hr as u32)) }
}

pub struct DeviceKey {
    key: usize,
    pub tpm: bool,
}

impl DeviceKey {
    /// Opens the named key, or creates it (TPM first, then software).
    /// An existing key is always reused, so the device identity stays stable.
    pub fn open_or_create(name: &str, machine: bool) -> Result<Self, String> {
        let flags = if machine { MACHINE_KEY } else { 0 };
        for create in [false, true] {
            for (provider, tpm) in [(TPM_PROVIDER, true), (SOFTWARE_PROVIDER, false)] {
                if let Ok(key) = open_in(provider, name, flags, create) {
                    return Ok(DeviceKey { key, tpm });
                }
            }
        }
        Err(format!("could not open or create key '{name}' in the TPM or software key store"))
    }

    /// Uncompressed SEC1 public key: 0x04 || X || Y (65 bytes).
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 72];
        let mut n = 0u32;
        let blob = wide("ECCPUBLICBLOB"); // BCRYPT_ECCPUBLIC_BLOB
        check(
            unsafe { NCryptExportKey(self.key, 0, blob.as_ptr(), std::ptr::null(), buf.as_mut_ptr(), 72, &mut n, 0) },
            "NCryptExportKey",
        )?;
        // BCRYPT_ECCKEY_BLOB header: magic (4 bytes) + cbKey (4 bytes), then X and Y.
        if n != 72 {
            return Err(format!("unexpected public key blob size {n}"));
        }
        let mut pk = vec![0x04];
        pk.extend_from_slice(&buf[8..72]);
        Ok(pk)
    }

    /// ECDSA P-256 signature over SHA-256(data), raw r||s (64 bytes).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let hash = Sha256::digest(data);
        let mut sig = [0u8; 64];
        let mut n = 0u32;
        check(
            unsafe { NCryptSignHash(self.key, std::ptr::null(), hash.as_ptr(), 32, sig.as_mut_ptr(), 64, &mut n, 0) },
            "NCryptSignHash",
        )?;
        Ok(sig[..n as usize].to_vec())
    }

    /// Deletes the key from the store (uninstall / tests).
    pub fn delete(&mut self) -> Result<(), String> {
        let key = std::mem::replace(&mut self.key, 0);
        check(unsafe { NCryptDeleteKey(key, 0) }, "NCryptDeleteKey")
    }
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        if self.key != 0 {
            unsafe { NCryptFreeObject(self.key) };
        }
    }
}

fn open_in(provider: &str, name: &str, flags: u32, create: bool) -> Result<usize, String> {
    let (name, alg) = (wide(name), wide("ECDSA_P256"));
    let mut prov = 0usize;
    check(unsafe { NCryptOpenStorageProvider(&mut prov, wide(provider).as_ptr(), 0) }, provider)?;
    let mut key = 0usize;
    let mut hr = unsafe { NCryptOpenKey(prov, &mut key, name.as_ptr(), 0, flags) };
    if hr == NTE_BAD_KEYSET && create {
        hr = unsafe { NCryptCreatePersistedKey(prov, &mut key, alg.as_ptr(), name.as_ptr(), 0, flags) };
        if hr == 0 {
            hr = unsafe { NCryptFinalizeKey(key, 0) };
            if hr != 0 {
                unsafe { NCryptFreeObject(key) };
            }
        }
    }
    unsafe { NCryptFreeObject(prov) };
    check(hr, provider).map(|_| key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    #[test]
    fn signature_verifies_with_p256_like_the_lambda() {
        let mut k = DeviceKey::open_or_create("TelltaleTestKey", false).unwrap();
        let pk = k.public_key().unwrap();
        let sig = k.sign(b"TT1 test").unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pk).unwrap();
        vk.verify(b"TT1 test", &Signature::from_slice(&sig).unwrap()).unwrap();
        assert!(vk.verify(b"TT1 other", &Signature::from_slice(&sig).unwrap()).is_err());
        k.delete().unwrap();
    }
}
