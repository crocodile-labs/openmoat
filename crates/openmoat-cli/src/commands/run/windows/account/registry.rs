//! The two machine-wide values setup writes (ADR-129 §1): the account's
//! `DWORD` 0 under Winlogon's `SpecialAccounts\UserList`, which leaves it off
//! the sign-in screen, and its SID under `HKLM\SOFTWARE\OpenMoat\AgentAccounts`,
//! which the hook relay reads (ADR-129 "The hook"). Only an administrator can
//! write either key; every account can read them. Foreign code, so this file
//! may use `unsafe`; each key it opens is closed by a guard.
//!
//! Microsoft's documentation:
//! - `RegCreateKeyExW`, `RegSetValueExW`, `RegGetValueW`, `RegDeleteValueW`,
//!   `RegDeleteKeyW`:
//!   <https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regcreatekeyexw>,
//!   <https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-reggetvaluew>.
//! - `HKEY_LOCAL_MACHINE\SOFTWARE`'s default access list (Users read,
//!   Administrators full control): "Registry Key Security and Access Rights",
//!   <https://learn.microsoft.com/windows/win32/sysinfo/registry-key-security-and-access-rights>.

use std::ptr;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW,
    RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

use super::wide;
use crate::agent_account::{RELAY_KEY, USER_LIST_KEY};

/// The parent of [`RELAY_KEY`], removed with it when empty.
const VENDOR_KEY: &str = r"SOFTWARE\OpenMoat";

/// A key this process opened, closed when dropped.
struct Key(HKEY);

impl Drop for Key {
    #[expect(unsafe_code, reason = "RegCloseKey is foreign code")]
    fn drop(&mut self) {
        // SAFETY: the key came from RegCreateKeyExW or RegOpenKeyExW and is
        // closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// `path` under HKLM, created when missing, open for setting values.
#[expect(unsafe_code, reason = "RegCreateKeyExW is foreign code")]
fn create(path: &str) -> Result<Key> {
    let path_w = wide(path)?;
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; no class, default security (the
    // parent's inherited list); `key` receives a key this process closes.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &raw mut key,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("opening HKLM\\{path}: Windows error {status}");
    }
    Ok(Key(key))
}

/// Set the value `name` of `key` to `data`, a `REG_DWORD` or `REG_SZ`.
#[expect(unsafe_code, reason = "RegSetValueExW is foreign code")]
fn set(key: &Key, name: &str, kind: u32, data: &[u8]) -> Result<()> {
    let name_w = wide(name)?;
    let Ok(len) = u32::try_from(data.len()) else {
        bail!("the value is too large");
    };
    // SAFETY: the key is open for setting; `data` holds `len` bytes.
    let status = unsafe { RegSetValueExW(key.0, name_w.as_ptr(), 0, kind, data.as_ptr(), len) };
    if status != ERROR_SUCCESS {
        bail!("setting the registry value {name}: Windows error {status}");
    }
    Ok(())
}

/// Delete the value `name` under `path`; one that is gone is fine.
#[expect(unsafe_code, reason = "registry calls are foreign code")]
fn delete(path: &str, name: &str) -> Result<()> {
    let path_w = wide(path)?;
    let name_w = wide(name)?;
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; `key` receives a key this process closes.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &raw mut key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if status != ERROR_SUCCESS {
        bail!("opening HKLM\\{path}: Windows error {status}");
    }
    let key = Key(key);
    // SAFETY: the key is open for setting; `name_w` is NUL-terminated.
    let status = unsafe { RegDeleteValueW(key.0, name_w.as_ptr()) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        bail!("deleting the registry value {name}: Windows error {status}");
    }
    Ok(())
}

/// The `DWORD` value `name` under `path`, if there is one.
#[expect(unsafe_code, reason = "RegGetValueW is foreign code")]
fn dword(path: &str, name: &str) -> Option<u32> {
    let path_w = wide(path).ok()?;
    let name_w = wide(name).ok()?;
    let mut value = 0_u32;
    let mut len = 4_u32;
    // SAFETY: both strings are NUL-terminated; `value` holds `len` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            name_w.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    (status == ERROR_SUCCESS).then_some(value)
}

/// The string value `name` under `path`, if there is one.
#[expect(unsafe_code, reason = "RegGetValueW is foreign code")]
fn string(path: &str, name: &str) -> Option<String> {
    let path_w = wide(path).ok()?;
    let name_w = wide(name).ok()?;
    // A SID is at most 184 characters; this is room enough, with its NUL.
    let mut value = vec![0_u16; 256];
    let mut len = u32::try_from(value.len() * 2).ok()?;
    // SAFETY: both strings are NUL-terminated; `value` holds `len` bytes, and
    // RegGetValueW NUL-terminates what it writes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            name_w.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = value.iter().position(|&u| u == 0).unwrap_or(value.len());
    Some(String::from_utf16_lossy(&value[..end]))
}

/// Leave `account` off the sign-in screen.
pub fn hide(account: &str) -> Result<()> {
    set(
        &create(USER_LIST_KEY)?,
        account,
        REG_DWORD,
        &0_u32.to_le_bytes(),
    )
}

/// Whether `account` is left off the sign-in screen.
pub fn hidden(account: &str) -> bool {
    dword(USER_LIST_KEY, account) == Some(0)
}

/// Show `account` on the sign-in screen again (it is about to be deleted).
pub fn unhide(account: &str) -> Result<()> {
    delete(USER_LIST_KEY, account)
}

/// Register the account `sid` as set up by the person `person`, for the
/// hook relay.
pub fn register(sid: &str, person: &str) -> Result<()> {
    let data: Vec<u8> = person
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    set(&create(RELAY_KEY)?, sid, REG_SZ, &data)
}

/// The person who registered the account `sid`, if an administrator did.
pub fn registered(sid: &str) -> Option<String> {
    string(RELAY_KEY, sid)
}

/// Take the account `sid` out of the relay's list; the keys go once empty.
pub fn unregister(sid: &str) -> Result<()> {
    delete(RELAY_KEY, sid)?;
    // Another person's account keeps the list.
    if !has_values(RELAY_KEY) {
        delete_key(RELAY_KEY);
        // Refused by Windows while it has another subkey: kept then.
        delete_key(VENDOR_KEY);
    }
    Ok(())
}

/// Delete the key `path` under HKLM, if it has no subkeys; best effort.
#[expect(unsafe_code, reason = "RegDeleteKeyW is foreign code")]
fn delete_key(path: &str) {
    if let Ok(path_w) = wide(path) {
        // SAFETY: `path_w` is NUL-terminated; a key with subkeys is refused.
        unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, path_w.as_ptr()) };
    }
}

/// Whether the key `path` holds any value.
#[expect(unsafe_code, reason = "RegQueryInfoKeyW is foreign code")]
fn has_values(path: &str) -> bool {
    use windows_sys::Win32::System::Registry::{KEY_QUERY_VALUE, RegQueryInfoKeyW};
    let Ok(path_w) = wide(path) else {
        return true;
    };
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; `key` receives a key this process closes.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &raw mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let key = Key(key);
    let mut values = 0_u32;
    // SAFETY: the key is open for queries; only the value count is asked.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut values,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    status != ERROR_SUCCESS || values > 0
}
