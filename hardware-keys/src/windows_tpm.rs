/// Windows TPM 2.0 backend for P-256/ES256 key operations
///
/// Uses CNG (Cryptography Next Generation) via the Microsoft Platform Crypto Provider.
/// Keys are generated inside the TPM and never leave the hardware. CNG persists keys
/// internally by name — no private key files on disk.
///
/// Key naming convention: `aauth-<label>` (e.g. `aauth-signing-key`)
/// Backend identifier: `"windows-tpm"`
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use napi::bindgen_prelude::*;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Foundation::*;

use crate::{GeneratedKey, HardwareKeyInfo, SignatureResult};

const KEY_NAME_PREFIX: &str = "hwkey-";

// Microsoft Platform Crypto Provider — TPM-backed key storage
const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// Check if TPM 2.0 is available via CNG Platform Crypto Provider
pub fn discover() -> Option<HardwareKeyInfo> {
    // Try to open the Platform Crypto Provider — fails if no TPM present
    let provider_name = HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER);
    let mut provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE::default();

    let status = unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            PCWSTR(provider_name.as_ptr()),
            0,
        )
    };

    if status.is_err() {
        return None;
    }

    unsafe { NCryptFreeObject(provider.0 as *mut _) };

    Some(HardwareKeyInfo {
        backend: "windows-tpm".to_string(),
        description: "Windows TPM 2.0 (Microsoft Platform Crypto Provider)".to_string(),
        algorithms: vec!["ES256".to_string()],
        device_id: "local".to_string(),
    })
}

/// Generate a P-256 key in the TPM.
///
/// # Parameters
/// - `label`              – Key name stored in CNG as `aauth-<label>`.
/// - `algorithm`          – Only `"ES256"` is supported.
/// - `require_biometric`  – When `true`, sets `NCRYPT_UI_POLICY_PROPERTY` requiring
///                          Windows Hello authentication before key use. Key creation
///                          fails rather than silently falling back to unprotected.
/// - `on_duplicate`       – Controls behaviour when a key with the same label already
///                          exists in the TPM.
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

    // Check if key already exists
    if tpm_key_exists(&key_name)? {
        match on_duplicate {
            DuplicateLabelPolicy::Replace => {
                delete_key(label)?;
            }
            DuplicateLabelPolicy::Error => {
                // Try to load existing key and return it (get-or-create)
                return load_and_export_key(&key_name, label);
            }
        }
    }

    let provider = open_provider()?;

    // Create persisted key in TPM
    let key_name_h = HSTRING::from(key_name.as_str());
    let mut key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key_handle,
            PCWSTR(HSTRING::from("ECDSA_P256").as_ptr()),
            PCWSTR(key_name_h.as_ptr()),
            AT_KEYEXCHANGE, // ignored for ECC but required
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptCreatePersistedKey failed: {}", e)))?;
    }

    // Set Windows Hello / UI policy if biometric requested
    if require_biometric {
        let policy = NCRYPT_UI_POLICY {
            dwVersion: 1,
            dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
            pszCreationTitle: PCWSTR::null(),
            pszFriendlyName: PCWSTR::null(),
            pszDescription: PCWSTR::null(),
        };

        let result = unsafe {
            NCryptSetProperty(
                key_handle,
                PCWSTR(HSTRING::from("UI Policy").as_ptr()),
                std::slice::from_raw_parts(
                    &policy as *const _ as *const u8,
                    std::mem::size_of::<NCRYPT_UI_POLICY>(),
                ),
                0,
            )
        };

        if result.is_err() {
            // Fail hard — do not silently create unprotected key
            unsafe { NCryptFreeObject(key_handle.0 as *mut _) };
            unsafe { NCryptFreeObject(provider.0 as *mut _) };
            return Err(Error::from_reason(format!(
                "Failed to set Windows Hello UI policy: {}. \
                 TPM key creation aborted to avoid creating unprotected key.",
                result.unwrap_err()
            )));
        }
    }

    // Finalize key — writes to TPM
    unsafe {
        NCryptFinalizeKey(key_handle, 0)
            .map_err(|e| {
                let _ = NCryptFreeObject(key_handle.0 as *mut _);
                let _ = NCryptFreeObject(provider.0 as *mut _);
                Error::from_reason(format!("NCryptFinalizeKey failed: {}", e))
            })?;
    }

    let public_jwk = export_public_jwk(key_handle)?;

    unsafe {
        NCryptFreeObject(key_handle.0 as *mut _);
        NCryptFreeObject(provider.0 as *mut _);
    }

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a TPM key.
/// `NCryptSignHash` returns a P1363 signature (r||s, 64 bytes) directly.
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let key_name = format!("{}{}", KEY_NAME_PREFIX, key_id);
    let key_handle = open_key(&key_name)?;

    // NCRYPT_NO_PADDING_FLAG for ECDSA raw hash signing
    let padding_info = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: PCWSTR(HSTRING::from("SHA256").as_ptr()),
    };

    let mut sig_len: u32 = 0;

    // First call: get required buffer size
    unsafe {
        NCryptSignHash(
            key_handle,
            Some(&padding_info as *const _ as *const _),
            hash,
            None,
            &mut sig_len,
            NCRYPT_NO_PADDING_FLAG,
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash (size query) failed: {}", e)))?;
    }

    let mut sig_buf = vec![0u8; sig_len as usize];

    // Second call: actual sign
    unsafe {
        NCryptSignHash(
            key_handle,
            Some(&padding_info as *const _ as *const _),
            hash,
            Some(&mut sig_buf),
            &mut sig_len,
            NCRYPT_NO_PADDING_FLAG,
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash failed: {}", e)))?;
    }

    sig_buf.truncate(sig_len as usize);

    // CNG returns P1363 (r||s, 64 bytes) for P-256 — this is what we want
    unsafe { NCryptFreeObject(key_handle.0 as *mut _) };

    Ok(SignatureResult {
        signature: sig_buf.into(),
        algorithm: "ES256".to_string(),
    })
}

/// List all TPM keys with the `aauth-` prefix.
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let provider = open_provider()?;
    let mut keys = Vec::new();

    let mut enum_state: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut key_name_buf = [0u16; 512];

    loop {
        let mut pcb_result: u32 = key_name_buf.len() as u32 * 2;
        let status = unsafe {
            NCryptEnumKeys(
                provider,
                PCWSTR::null(),
                &mut (key_name_buf.as_mut_ptr() as *mut NCryptKeyName),
                &mut enum_state,
                NCRYPT_SILENT_FLAG,
            )
        };

        match status {
            Ok(_) => {
                let name = String::from_utf16_lossy(
                    &key_name_buf[..key_name_buf
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(key_name_buf.len())],
                );

                if let Some(label) = name.strip_prefix(KEY_NAME_PREFIX) {
                    if let Ok(entry) = load_and_export_key(&name, label) {
                        keys.push(entry);
                    }
                }
            }
            Err(e) if e.code() == NTE_NO_MORE_ITEMS.into() => break,
            Err(e) => {
                unsafe { NCryptFreeBuffer(enum_state) };
                unsafe { NCryptFreeObject(provider.0 as *mut _) };
                return Err(Error::from_reason(format!("NCryptEnumKeys failed: {}", e)));
            }
        }

        let _ = pcb_result; // suppress unused warning
    }

    unsafe {
        if !enum_state.is_null() {
            NCryptFreeBuffer(enum_state);
        }
        NCryptFreeObject(provider.0 as *mut _);
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
        NCryptDeleteKey(key_handle, 0)
            .map_err(|e| Error::from_reason(format!("NCryptDeleteKey failed: {}", e)))?;
    }

    // NCryptDeleteKey frees the handle itself — do not call NCryptFreeObject

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

pub enum DuplicateLabelPolicy {
    Replace,
    Error,
}

/// Open the Microsoft Platform Crypto Provider
fn open_provider() -> Result<NCRYPT_PROV_HANDLE> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            PCWSTR(HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER).as_ptr()),
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptOpenStorageProvider failed: {}", e)))?;
    }
    Ok(provider)
}

/// Open an existing TPM key by CNG name
fn open_key(key_name: &str) -> Result<NCRYPT_KEY_HANDLE> {
    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptOpenKey(
            provider,
            &mut key_handle,
            PCWSTR(HSTRING::from(key_name).as_ptr()),
            AT_KEYEXCHANGE,
            NCRYPT_SILENT_FLAG,
        )
        .map_err(|e| {
            let _ = NCryptFreeObject(provider.0 as *mut _);
            Error::from_reason(format!("NCryptOpenKey failed for '{}': {}", key_name, e))
        })?;
    }

    unsafe { NCryptFreeObject(provider.0 as *mut _) };
    Ok(key_handle)
}

/// Returns true if a CNG key with the given name exists in the TPM
fn tpm_key_exists(key_name: &str) -> Result<bool> {
    match open_key(key_name) {
        Ok(handle) => {
            unsafe { NCryptFreeObject(handle.0 as *mut _) };
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Open an existing TPM key, export its public key, and return a GeneratedKey
fn load_and_export_key(key_name: &str, label: &str) -> Result<GeneratedKey> {
    let key_handle = open_key(key_name)?;
    let public_jwk = export_public_jwk(key_handle)?;
    unsafe { NCryptFreeObject(key_handle.0 as *mut _) };

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Export the public key from a CNG key handle and convert to JWK
fn export_public_jwk(key_handle: NCRYPT_KEY_HANDLE) -> Result<String> {
    // Export as BCRYPT_ECCPUBLIC_BLOB
    let blob_type = HSTRING::from("ECCPUBLICBLOB");
    let mut export_len: u32 = 0;

    // First call: get size
    unsafe {
        NCryptExportKey(
            key_handle,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            None,
            &mut export_len,
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptExportKey (size) failed: {}", e)))?;
    }

    let mut blob = vec![0u8; export_len as usize];

    // Second call: export
    unsafe {
        NCryptExportKey(
            key_handle,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            Some(&mut blob),
            &mut export_len,
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptExportKey failed: {}", e)))?;
    }

    blob.truncate(export_len as usize);
    eccpublic_blob_to_jwk(&blob)
}

/// Convert a `BCRYPT_ECCPUBLIC_BLOB` to JWK.
///
/// BCRYPT_ECCPUBLIC_BLOB layout:
///   DWORD dwMagic     (4 bytes) — e.g. BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345
///   DWORD cbKey       (4 bytes) — key size in bytes (32 for P-256)
///   BYTE  X[cbKey]
///   BYTE  Y[cbKey]
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

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    Ok(format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256","use":"sig"}}"#,
        x_b64, y_b64
    ))
}
