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

// ---------------------------------------------------------------------------
// RAII handle wrapper — mirrors enclaveapp-windows/provider.rs NcryptHandle
// ---------------------------------------------------------------------------

struct NcryptHandle(NCRYPT_HANDLE);

impl NcryptHandle {
    fn as_prov(&self) -> NCRYPT_PROV_HANDLE {
        NCRYPT_PROV_HANDLE(self.0 .0)
    }

    fn as_key(&self) -> NCRYPT_KEY_HANDLE {
        NCRYPT_KEY_HANDLE(self.0 .0)
    }
}

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check if TPM 2.0 is available via CNG Platform Crypto Provider.
/// The Microsoft Platform Crypto Provider only opens successfully when
/// backed by real TPM 2.0 hardware — no software fallback.
pub fn discover() -> Option<HardwareKeyInfo> {
    if open_provider().is_err() {
        eprintln!("[windows-tpm] discover: NCryptOpenStorageProvider failed");
        return None;
    }

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
/// - `label`              – Key name stored in CNG as `hwkey-<label>`.
/// - `algorithm`          – Only `"ES256"` is supported.
/// - `require_biometric`  – When `true`, sets `NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG`
///                          requiring Windows Hello authentication before every signing
///                          operation. Key creation fails rather than silently creating
///                          an unprotected key if the policy cannot be applied.
/// - `on_duplicate`       – Controls behaviour when a key with the same label already
///                          exists in the TPM. `Error` performs get-or-create (returns
///                          the existing key); `Replace` deletes and re-creates.
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
            // get-or-create: return existing key
            DuplicateLabelPolicy::Error => return load_and_export_key(&key_name, label),
        }
    }

    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptCreatePersistedKey(
            provider.as_prov(),
            &mut key_handle,
            &HSTRING::from("ECDSA_P256"),
            &HSTRING::from(key_name.as_str()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptCreatePersistedKey failed: {}", e)))?;
    }

    // Wrap immediately so handle is freed on any early return
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Set Windows Hello UI policy if biometric requested.
    // NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG prompts Windows Hello on every sign,
    // not on key creation. Fail hard rather than silently create an unprotected key.
    if require_biometric {
        // These strings are shown in the Windows Hello prompt UI.
        // Must be kept alive for the duration of NCryptSetProperty.
        let creation_title: Vec<u16> = "Hardware Key Authentication\0"
            .encode_utf16().collect();
        let friendly_name: Vec<u16> = format!("hwkey-{}\0", label)
            .encode_utf16().collect();
        let description: Vec<u16> = "Windows Hello is required to use this key\0"
            .encode_utf16().collect();

        let policy = NCRYPT_UI_POLICY {
            dwVersion: 1,
            dwFlags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
            pszCreationTitle: PCWSTR(creation_title.as_ptr()),
            pszFriendlyName: PCWSTR(friendly_name.as_ptr()),
            pszDescription: PCWSTR(description.as_ptr()),
        };

        unsafe {
            NCryptSetProperty(
                key.as_key(),
                &HSTRING::from("UI Policy"),
                std::slice::from_raw_parts(
                    &policy as *const _ as *const u8,
                    std::mem::size_of::<NCRYPT_UI_POLICY>(),
                ),
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| {
                Error::from_reason(format!(
                    "Failed to set Windows Hello UI policy: {}. \
                     TPM key creation aborted to avoid creating unprotected key.",
                    e
                ))
            })?;
        }

        // Explicitly keep the string buffers alive past NCryptSetProperty
        drop((creation_title, friendly_name, description));
    }

    unsafe {
        NCryptFinalizeKey(key.as_key(), NCRYPT_FLAGS(0))
            .map_err(|e| Error::from_reason(format!("NCryptFinalizeKey failed: {}", e)))?;
    }

    let public_jwk = export_public_jwk(&key)?;

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a TPM key.
/// CNG returns a P1363 signature (r ‖ s, 64 bytes) directly for ECDSA — no padding info needed.
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let key_name = format!("{}{}", KEY_NAME_PREFIX, key_id);
    let key = open_key(&key_name)?;

    // First call: query required signature buffer size
    let mut sig_len: u32 = 0;
    unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            hash,
            None,
            &mut sig_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash (size query) failed: {}", e)))?;
    }

    let mut sig_buf = vec![0u8; sig_len as usize];

    // Second call: actual sign — Windows Hello prompt fires here if biometric policy is set
    unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            hash,
            Some(&mut sig_buf),
            &mut sig_len,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash failed: {}", e)))?;
    }

    sig_buf.truncate(sig_len as usize);

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
                provider.as_prov(),
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
                        (*key_name_ptr).pszName.to_string().unwrap_or_default()
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
            Err(_) => break, // any other error ends enumeration gracefully
        }
    }

    if !enum_state.is_null() {
        unsafe { let _ = NCryptFreeBuffer(enum_state); }
    }

    Ok(keys)
}

/// Delete a TPM key by label.
/// Note: `NCryptDeleteKey` takes ownership of the handle and frees it — do NOT wrap in NcryptHandle.
pub fn delete_key(label: &str) -> Result<()> {
    let key_name = format!("{}{}", KEY_NAME_PREFIX, label);
    let key = open_key(&key_name).map_err(|_| {
        Error::from_reason(format!("Key not found for label: '{}'", label))
    })?;

    // NCryptDeleteKey takes ownership — must not let NcryptHandle drop call NCryptFreeObject again
    let raw = key.as_key();
    std::mem::forget(key);

    unsafe {
        NCryptDeleteKey(raw, 0)
            .map_err(|e| Error::from_reason(format!("NCryptDeleteKey failed: {}", e)))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn open_provider() -> Result<NcryptHandle> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            &HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER),
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptOpenStorageProvider failed: {}", e)))?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(provider.0)))
}

fn open_key(key_name: &str) -> Result<NcryptHandle> {
    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            &HSTRING::from(key_name),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
        .map_err(|e| {
            Error::from_reason(format!("NCryptOpenKey failed for '{}': {}", key_name, e))
        })?;
    }

    Ok(NcryptHandle(NCRYPT_HANDLE(key_handle.0)))
}

fn tpm_key_exists(key_name: &str) -> Result<bool> {
    Ok(open_key(key_name).is_ok())
}

fn load_and_export_key(key_name: &str, label: &str) -> Result<GeneratedKey> {
    let key = open_key(key_name)?;
    let public_jwk = export_public_jwk(&key)?;

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: label.to_string(),
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Export the public key from a CNG key handle and convert to JWK.
/// Uses two-call pattern: first query size, then export.
fn export_public_jwk(key: &NcryptHandle) -> Result<String> {
    let blob_type = HSTRING::from("ECCPUBLICBLOB");
    let mut export_len: u32 = 0;

    unsafe {
        NCryptExportKey(
            key.as_key(),
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
            key.as_key(),
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

/// Convert `BCRYPT_ECCPUBLIC_BLOB` to JWK.
///
/// Layout: `DWORD dwMagic (4) | DWORD cbKey (4) | BYTE X[cbKey] | BYTE Y[cbKey]`
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
