/// Windows TPM 2.0 backend for P-256/ES256 key operations
///
/// Uses CNG (Cryptography Next Generation) via the Microsoft Platform Crypto Provider.
/// Keys are generated inside the TPM and never leave the hardware. CNG persists keys
/// internally by name — no private key files on disk.
///
/// Key naming convention: `hwkey-<label>` (e.g. `hwkey-signing-key`)
/// Backend identifier: `"windows-tpm"`
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use napi::bindgen_prelude::*;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::*;

use crate::{GeneratedKey, HardwareKeyInfo, SignatureResult};

const KEY_NAME_PREFIX: &str = "hwkey-";
const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";

pub enum DuplicateLabelPolicy {
    Replace,
    Error,
}

/// Check if TPM 2.0 is available via CNG Platform Crypto Provider
pub fn discover() -> Option<HardwareKeyInfo> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    let status = unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            &HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER),
            0,
        )
    };
    if status.is_err() {
        return None;
    }
    unsafe { let _ = NCryptFreeObject(provider); }

    Some(HardwareKeyInfo {
        backend: "windows-tpm".to_string(),
        description: "Windows TPM 2.0 (Microsoft Platform Crypto Provider)".to_string(),
        algorithms: vec!["ES256".to_string()],
        device_id: "local".to_string(),
    })
}

/// Generate a P-256 key in the TPM.
pub fn generate_key(
    label: &str,
    algorithm: &str,
    require_biometric: bool,
    on_duplicate: DuplicateLabelPolicy,
) -> Result<GeneratedKey> {
    if algorithm != "ES256" {
        return Err(Error::from_reason(
            "TPM Windows backend only supports ES256 (P-256)",
        ));
    }

    let key_name = format!("{}{}", KEY_NAME_PREFIX, label);

    if tpm_key_exists(&key_name)? {
        match on_duplicate {
            DuplicateLabelPolicy::Replace => delete_key(label)?,
            DuplicateLabelPolicy::Error => return load_and_export_key(&key_name, label),
        }
    }

    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key_handle,
            &HSTRING::from("ECDSA_P256"),
            &HSTRING::from(key_name.as_str()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            let _ = NCryptFreeObject(provider);
            Error::from_reason(format!("NCryptCreatePersistedKey failed: {}", e))
        })?;
    }

    // Set Windows Hello UI policy if biometric requested
    if require_biometric {
        let policy = NCRYPT_UI_POLICY {
            dwVersion: 1,
            dwFlags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
            pszCreationTitle: PCWSTR::null(),
            pszFriendlyName: PCWSTR::null(),
            pszDescription: PCWSTR::null(),
        };

        let result = unsafe {
            NCryptSetProperty(
                key_handle,
                &HSTRING::from("UI Policy"),
                std::slice::from_raw_parts(
                    &policy as *const _ as *const u8,
                    std::mem::size_of::<NCRYPT_UI_POLICY>(),
                ),
                NCRYPT_FLAGS(0),
            )
        };

        if result.is_err() {
            unsafe {
                let _ = NCryptFreeObject(key_handle);
                let _ = NCryptFreeObject(provider);
            }
            return Err(Error::from_reason(format!(
                "Failed to set Windows Hello UI policy: {}. \
                 TPM key creation aborted to avoid creating unprotected key.",
                result.unwrap_err()
            )));
        }
    }

    unsafe {
        NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)).map_err(|e| {
            let _ = NCryptFreeObject(key_handle);
            let _ = NCryptFreeObject(provider);
            Error::from_reason(format!("NCryptFinalizeKey failed: {}", e))
        })?;
    }

    let public_jwk = export_public_jwk(key_handle)?;

    unsafe {
        let _ = NCryptFreeObject(key_handle);
        let _ = NCryptFreeObject(provider);
    }

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a TPM key.
/// NCryptSignHash returns a P1363 signature (r||s, 64 bytes) directly.
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let key_name = format!("{}{}", KEY_NAME_PREFIX, key_id);
    let key_handle = open_key(&key_name)?;

    let mut sig_len: u32 = 0;

    // First call: get required buffer size
    unsafe {
        NCryptSignHash(
            key_handle,
            None,
            hash,
            None,
            &mut sig_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash (size query) failed: {}", e)))?;
    }

    let mut sig_buf = vec![0u8; sig_len as usize];

    // Second call: actual sign
    unsafe {
        NCryptSignHash(
            key_handle,
            None,
            hash,
            Some(&mut sig_buf),
            &mut sig_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash failed: {}", e)))?;
    }

    sig_buf.truncate(sig_len as usize);

    unsafe { let _ = NCryptFreeObject(key_handle); }

    Ok(SignatureResult {
        signature: sig_buf.into(),
        algorithm: "ES256".to_string(),
    })
}

/// List all TPM keys with the `hwkey-` prefix.
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let provider = open_provider()?;
    let mut keys = Vec::new();
    let mut enum_state: *mut core::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut key_name_ptr: *mut NCryptKeyName = std::ptr::null_mut();

        let status = unsafe {
            NCryptEnumKeys(
                provider,
                PCWSTR::null(),
                &mut key_name_ptr,
                &mut enum_state,
                NCRYPT_SILENT_FLAG,
            )
        };

        match status {
            Ok(_) => {
                if !key_name_ptr.is_null() {
                    let name = unsafe {
                        (*key_name_ptr).pszName.to_string()
                            .unwrap_or_default()
                    };
                    unsafe { let _ = NCryptFreeBuffer(key_name_ptr as *mut _); }

                    if let Some(label) = name.strip_prefix(KEY_NAME_PREFIX) {
                        if let Ok(entry) = load_and_export_key(&name, label) {
                            keys.push(entry);
                        }
                    }
                }
            }
            Err(e) if e.code() == windows::Win32::Foundation::NTE_NO_MORE_ITEMS.into() => break,
            Err(e) => {
                unsafe {
                    if !enum_state.is_null() {
                        let _ = NCryptFreeBuffer(enum_state);
                    }
                    let _ = NCryptFreeObject(provider);
                }
                return Err(Error::from_reason(format!("NCryptEnumKeys failed: {}", e)));
            }
        }
    }

    unsafe {
        if !enum_state.is_null() {
            let _ = NCryptFreeBuffer(enum_state);
        }
        let _ = NCryptFreeObject(provider);
    }

    Ok(keys)
}

/// Delete a TPM key by label.
pub fn delete_key(label: &str) -> Result<()> {
    let key_name = format!("{}{}", KEY_NAME_PREFIX, label);
    let key_handle = open_key(&key_name).map_err(|_| {
        Error::from_reason(format!("Key not found for label: '{}'", label))
    })?;

    unsafe {
        // NCryptDeleteKey frees the handle itself — do not call NCryptFreeObject after
        NCryptDeleteKey(key_handle, 0)
            .map_err(|e| Error::from_reason(format!("NCryptDeleteKey failed: {}", e)))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn open_provider() -> Result<NCRYPT_PROV_HANDLE> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            &HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER),
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptOpenStorageProvider failed: {}", e)))?;
    }
    Ok(provider)
}

fn open_key(key_name: &str) -> Result<NCRYPT_KEY_HANDLE> {
    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    let result = unsafe {
        NCryptOpenKey(
            provider,
            &mut key_handle,
            &HSTRING::from(key_name),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    };

    unsafe { let _ = NCryptFreeObject(provider); }

    result.map_err(|e| {
        Error::from_reason(format!("NCryptOpenKey failed for '{}': {}", key_name, e))
    })?;

    Ok(key_handle)
}

fn tpm_key_exists(key_name: &str) -> Result<bool> {
    match open_key(key_name) {
        Ok(handle) => {
            unsafe { let _ = NCryptFreeObject(handle); }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn load_and_export_key(key_name: &str, label: &str) -> Result<GeneratedKey> {
    let key_handle = open_key(key_name)?;
    let public_jwk = export_public_jwk(key_handle)?;
    unsafe { let _ = NCryptFreeObject(key_handle); }

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

fn export_public_jwk(key_handle: NCRYPT_KEY_HANDLE) -> Result<String> {
    let blob_type = HSTRING::from("ECCPUBLICBLOB");
    let mut export_len: u32 = 0;

    unsafe {
        NCryptExportKey(
            key_handle,
            NCRYPT_KEY_HANDLE::default(),
            &blob_type,
            None,
            None,
            &mut export_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptExportKey (size) failed: {}", e)))?;
    }

    let mut blob = vec![0u8; export_len as usize];

    unsafe {
        NCryptExportKey(
            key_handle,
            NCRYPT_KEY_HANDLE::default(),
            &blob_type,
            None,
            Some(&mut blob),
            &mut export_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptExportKey failed: {}", e)))?;
    }

    blob.truncate(export_len as usize);
    eccpublic_blob_to_jwk(&blob)
}

/// Convert BCRYPT_ECCPUBLIC_BLOB to JWK.
///
/// Layout: DWORD dwMagic (4) | DWORD cbKey (4) | BYTE X[cbKey] | BYTE Y[cbKey]
fn eccpublic_blob_to_jwk(blob: &[u8]) -> Result<String> {
    if blob.len() < 8 {
        return Err(Error::from_reason("ECCPUBLIC blob too short"));
    }

    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;

    if blob.len() < 8 + cb_key * 2 {
        return Err(Error::from_reason("ECCPUBLIC blob truncated"));
    }

    let x = &blob[8..8 + cb_key];
    let y = &blob[8 + cb_key..8 + cb_key * 2];

    Ok(format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256","use":"sig"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y),
    ))
}
