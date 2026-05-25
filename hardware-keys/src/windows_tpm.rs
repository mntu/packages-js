/// Windows TPM 2.0 backend for P-256/ES256 key operations
///
/// Uses CNG (Cryptography Next Generation) via the Microsoft Platform Crypto Provider.
/// Keys are generated inside the TPM and never leave the hardware. CNG persists keys
/// internally by name — no private key files on disk.
///
/// Key naming convention: `hwkey-<label>` (e.g. `hwkey-signing-key`)
/// Backend identifier: `"windows-tpm"`
///
/// ## Windows Hello
///
/// When `require_biometric: true`, Windows Hello is prompted via
/// `Windows.Security.Credentials.UI.UserConsentVerifier` before `sign_hash`.
/// The key itself is created without `NCRYPT_UI_POLICY` so CNG never shows
/// its own legacy CryptUI password dialog. The Hello prompt is surfaced at the
/// application level — this is a soft gate (same-UID attacker with code execution
/// can hook the result), but delivers proper biometric UX on Hello-enrolled hosts.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use napi::bindgen_prelude::*;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::*;
use std::thread;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier,
    UserConsentVerifierAvailability,
};

use crate::{GeneratedKey, HardwareKeyInfo, SignatureResult};

const KEY_NAME_PREFIX: &str = "hwkey-";
const KEY_NAME_PREFIX_BIO: &str = "hwkey-bio-";

/// The CNG provider name for TPM-backed keys.
pub const PLATFORM_PROVIDER: &str = "Microsoft Platform Crypto Provider";

pub enum DuplicateLabelPolicy {
    Replace,
    Error,
}

// ---------------------------------------------------------------------------
// RAII handle wrapper
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
/// - `label`              – Key name stored in CNG as `hwkey-<label>` or `hwkey-bio-<label>`.
/// - `algorithm`          – Only `"ES256"` is supported.
/// - `require_biometric`  – When `true`, Windows Hello will be prompted via
///                          `UserConsentVerifier` before every `sign_hash` call.
///                          The key itself is created without any CNG UI policy —
///                          the Hello gate is enforced at the application level.
/// - `on_duplicate`       – Controls behaviour when a key with the same label already
///                          exists. `Error` performs get-or-create; `Replace` deletes
///                          and re-creates.
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

    // Verify Windows Hello is available before creating a biometric-gated key.
    // Fail hard rather than silently create a key that can never be used with Hello.
    if require_biometric && !hello_available() {
        return Err(Error::from_reason(
            "Windows Hello is not configured for this user. \
             Set up a PIN or biometric in Windows Settings before creating a biometric-gated key.",
        ));
    }

    let key_name = if require_biometric {
        format!("{}{}", KEY_NAME_PREFIX_BIO, label)
    } else {
        format!("{}{}", KEY_NAME_PREFIX, label)
    };

    if tpm_key_exists(&key_name)? {
        match on_duplicate {
            DuplicateLabelPolicy::Replace => delete_key(&key_name)?,
            // get-or-create: return existing key
            DuplicateLabelPolicy::Error => return load_and_export_key(&key_name),
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
            CERT_KEY_SPEC::default(),
            NCRYPT_SILENT_FLAG, // prevent CNG from showing its own UI dialog
        )
        .map_err(|e| Error::from_reason(format!("NCryptCreatePersistedKey failed: {}", e)))?;
    }

    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    unsafe {
        // NCRYPT_SILENT_FLAG: fail closed (NTE_SILENT_CONTEXT) rather than show dialog
        NCryptFinalizeKey(key.as_key(), NCRYPT_SILENT_FLAG)
            .map_err(|e| Error::from_reason(format!("NCryptFinalizeKey failed: {}", e)))?;
    }
    println!("Created with key_name: {}", key_name);
    let public_jwk = export_public_jwk(&key)?;

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: key_name, // full key_id: "hwkey-<label>" or "hwkey-bio-<label>"
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a TPM key.
///
/// `key_id` is the full key name returned by `generate_key`:
/// - `"hwkey-<label>"` — no biometric, signs immediately.
/// - `"hwkey-bio-<label>"` — prompts Windows Hello before signing.
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let require_biometric = key_id.starts_with(KEY_NAME_PREFIX_BIO);
    sign_hash_with_options(key_id, hash, require_biometric)
}

fn sign_hash_with_options(key_id: &str, hash: &[u8], require_biometric: bool) -> Result<SignatureResult> {
    if require_biometric {
        let reason = format!("Authenticate to sign with key '{}'", key_id);
        hello_verify(&reason)?;
    }

    // key_id is already the full CNG key name (e.g. "hwkey-signing-key" or "hwkey-bio-signing-key")
    let key = open_key(key_id)?;

    // First call: query required signature buffer size
    let mut sig_len: u32 = 0;
    unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            hash,
            None,
            &mut sig_len,
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| Error::from_reason(format!("NCryptSignHash (size query) failed: {}", e)))?;
    }

    let mut sig_buf = vec![0u8; sig_len as usize];

    // Second call: actual sign — Windows Hello prompt fires before this if biometric
    unsafe {
        NCryptSignHash(
            key.as_key(),
            None,
            hash,
            Some(&mut sig_buf),
            &mut sig_len,
            NCRYPT_FLAGS::default(),
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

                    // Only include keys managed by this library (hwkey- or hwkey-bio- prefix)
                    if name.starts_with(KEY_NAME_PREFIX) {
                        println!("[list_keys] raw pszName: '{}'", name);
                        if let Ok(entry) = load_and_export_key(&name) {
                            keys.push(entry);
                        }
                    }
                }
            }
            Err(e) if e.code() == windows::Win32::Foundation::NTE_NO_MORE_ITEMS.into() => break,
            Err(_) => break,
        }
    }

    if !enum_state.is_null() {
        unsafe { let _ = NCryptFreeBuffer(enum_state); }
    }

    Ok(keys)
}

/// Delete a TPM key by its full key_id (e.g. `"hwkey-signing-key"` or `"hwkey-bio-signing-key"`).
/// `NCryptDeleteKey` takes ownership of the handle — must NOT call NCryptFreeObject after.
pub fn delete_key(key_id: &str) -> Result<()> {
    println!("delete_key key_id: '{}'", key_id);
    let key = open_key(key_id).map_err(|_| {
        Error::from_reason(format!("Key not found for key_id: '{}'", key_id))
    })?;

    let raw = key.as_key();
    std::mem::forget(key);

    unsafe {
        NCryptDeleteKey(raw, 0)
            .map_err(|e| Error::from_reason(format!("NCryptDeleteKey failed: {}", e)))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Hello helpers
// ---------------------------------------------------------------------------
fn run_on_sta<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        unsafe {
            let _ = windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_APARTMENTTHREADED,
            );
        }
        let result = f();
        unsafe { windows::Win32::System::Com::CoUninitialize(); }
        let _ = tx.send(result);
    });
    rx.recv().map_err(|_| Error::from_reason("STA thread died"))?
}

/// Check whether Windows Hello (PIN or biometric) is configured for the current user.
fn hello_available() -> bool {
    run_on_sta(|| {
        let async_op = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let result = async_op.get()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(matches!(result, UserConsentVerifierAvailability::Available))
    }).unwrap_or(false)
}

/// Prompt Windows Hello synchronously. Returns `Ok(())` on `Verified`,
/// `Err` on cancellation, device not present, policy disabled, or retries exhausted.
fn hello_verify(reason: &str) -> Result<()> {
    let reason = reason.to_string();
    run_on_sta(move || prompt_user_consent(&reason))
}

/// Fire the Hello biometric/PIN prompt synchronously. Returns `Ok(())`
/// on `Verified`; otherwise returns an `Error::KeyOperation` describing
/// why the verification did not succeed (user cancelled, device busy,
/// disabled by policy, etc.).
fn prompt_user_consent(reason: &str) -> Result<()> {
    let reason_h = HSTRING::from(reason);
    let async_op = UserConsentVerifier::RequestVerificationAsync(&reason_h).map_err(|e| {
        Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: format!("UserConsentVerifier::RequestVerificationAsync: {e}"),
        }
    })?;
    let result = async_op.get().map_err(|e| Error::KeyOperation {
        operation: "hello_await_result".into(),
        detail: format!("UserConsentVerifier async wait: {e}"),
    })?;

    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::DeviceNotPresent => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "Windows Hello is not configured for this user (DeviceNotPresent)".into(),
        }),
        UserConsentVerificationResult::NotConfiguredForUser => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "Windows Hello is not configured for this user (NotConfiguredForUser)".into(),
        }),
        UserConsentVerificationResult::DisabledByPolicy => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "Windows Hello is disabled by policy".into(),
        }),
        UserConsentVerificationResult::DeviceBusy => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "Windows Hello device is busy; try again".into(),
        }),
        UserConsentVerificationResult::RetriesExhausted => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "Windows Hello retries exhausted; user could not be verified".into(),
        }),
        UserConsentVerificationResult::Canceled => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: "User cancelled Windows Hello verification".into(),
        }),
        other => Err(Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: format!("UserConsentVerifier returned unexpected result {other:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn open_provider() -> Result<NcryptHandle> {
    let provider_name: Vec<u16> = PLATFORM_PROVIDER
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut handle = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut handle,
            PCWSTR(provider_name.as_ptr()),
            0,
        )
        .map_err(|e| Error::from_reason(format!("NCryptOpenStorageProvider failed: {}", e)))?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(handle.0)))
}

fn open_key(key_name: &str) -> Result<NcryptHandle> {
    let provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();

    unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            &HSTRING::from(key_name),
            CERT_KEY_SPEC::default(),
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

fn load_and_export_key(key_id: &str) -> Result<GeneratedKey> {
    println!("load_and_export_key key_id: '{}'", key_id);
    let key = open_key(key_id)?;
    let public_jwk = export_public_jwk(&key)?;

    Ok(GeneratedKey {
        backend: "windows-tpm".to_string(),
        key_id: key_id.to_string(), // full key_id preserved
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

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
            NCRYPT_FLAGS::default(),
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
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| Error::from_reason(format!("NCryptExportKey failed: {}", e)))?;
    }

    blob.truncate(export_len as usize);
    eccpublic_blob_to_jwk(&blob)
}

/// Convert `BCRYPT_ECCPUBLIC_BLOB` to JWK.
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
