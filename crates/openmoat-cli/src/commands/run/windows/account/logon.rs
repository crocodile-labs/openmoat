//! Starting the agent as the account, and the secrets around it (ADR-129):
//! the password encrypted for the person with DPAPI, whether this process is
//! elevated, whose token a process has, and `CreateProcessWithLogonW`.
//! Foreign code, so this file may use `unsafe`; what Windows allocates is
//! freed by a guard, and decrypted bytes are cleared before they are freed.
//!
//! Microsoft's documentation:
//! - `CryptProtectData` / `CryptUnprotectData` (user scope: "only a user with
//!   the same logon credential as the user who encrypted the data can
//!   decrypt"):
//!   <https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata>.
//! - `TokenElevation`:
//!   <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_elevation>.
//! - `CreateProcessWithLogonW` (`LOGON_WITH_PROFILE`, the Secondary Logon
//!   service, `lpCommandLine` at most 1024 characters, the handles in
//!   `STARTUPINFO` with `STARTF_USESTDHANDLES`, full access to the returned
//!   process and thread handles):
//!   <https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw>.
//! - `DeleteProfileW`:
//!   <https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-deleteprofilew>.

use std::ptr;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW, GetCurrentProcess,
    LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::DeleteProfileW;
use zeroize::{Zeroize as _, Zeroizing};

use super::super::win32::{
    Job, Local, Owned, Started, contain, last_error, standard_handles, token_info, user_sid,
};
use super::wide;

/// What DPAPI files the secret under, in its own header.
const DESCRIPTION: &str = "OpenMoat agent account";

/// `bytes` encrypted for the person's logon (DPAPI, user scope).
#[expect(unsafe_code, reason = "CryptProtectData is foreign code")]
pub fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    let Ok(len) = u32::try_from(bytes.len()) else {
        bail!("the secret is too large");
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let description = wide(DESCRIPTION)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` describes `bytes`, which DPAPI only reads; no entropy,
    // no prompt; `output` receives a LocalAlloc'd buffer this function frees.
    let done = unsafe {
        CryptProtectData(
            &raw const input,
            description.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if done == 0 {
        bail!("encrypting the account's password: {}", last_error());
    }
    let _free = Local(output.pbData.cast());
    // SAFETY: DPAPI wrote `cbData` bytes at `pbData`.
    let blob = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    Ok(blob.to_vec())
}

/// What [`protect`] encrypted, decrypted under this logon; the copy Windows
/// made is cleared before it is freed.
#[expect(unsafe_code, reason = "CryptUnprotectData is foreign code")]
pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let Ok(len) = u32::try_from(blob.len()) else {
        bail!("the encrypted password is too large");
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: blob.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` describes `blob`, which DPAPI only reads; no
    // description asked back, no entropy, no prompt.
    let done = unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if done == 0 {
        bail!(
            "decrypting the agent account's password (only your own logon can): {}",
            last_error()
        );
    }
    let _free = Local(output.pbData.cast());
    // SAFETY: DPAPI wrote `cbData` writable bytes at `pbData`, freed only
    // when `_free` drops after this.
    let plain = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copy = Zeroizing::new(plain.to_vec());
    plain.zeroize();
    Ok(copy)
}

/// This process's token, open for queries.
#[expect(unsafe_code, reason = "OpenProcessToken is foreign code")]
fn own_token() -> Result<Owned> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: a pseudo-handle that needs no closing; `token` receives a
    // handle this process owns.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        bail!("opening this process's token: {}", last_error());
    }
    Ok(Owned(token))
}

/// Whether this process runs with an administrator's full token (an
/// elevated terminal), not the filtered one User Account Control gives.
#[expect(unsafe_code, reason = "reading TOKEN_ELEVATION that Windows wrote")]
pub fn elevated() -> Result<bool> {
    let token = own_token()?;
    let buffer = token_info(token.0, TokenElevation)?;
    // SAFETY: GetTokenInformation wrote a TOKEN_ELEVATION at the start of
    // the aligned `buffer`.
    let elevation = unsafe { &*buffer.as_ptr().cast::<TOKEN_ELEVATION>() };
    Ok(elevation.TokenIsElevated != 0)
}

/// The SID of this process's user.
pub fn current_user() -> Result<String> {
    user_sid(own_token()?.0)
}

/// The SID of the user of `process`'s token; `None` when it cannot be read.
#[expect(unsafe_code, reason = "OpenProcessToken is foreign code")]
fn process_user(process: &Owned) -> Option<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process` is open with every right (CreateProcessWithLogonW
    // returns full access); `token` receives a handle this process owns.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) } == 0 {
        return None;
    }
    user_sid(Owned(token).0).ok()
}

/// The agent, started suspended as the account and put in the job, and
/// whether its token's user, read back before it ran, is `sid`.
pub struct AsAccount {
    pub started: Started,
    pub user_is_account: bool,
}

/// Start `application` with command line `line` and environment block `env`
/// as `account`, whose password is `password` (NUL-terminated UTF-16, which
/// the caller clears), loading its profile, suspended; put it in `job`.
#[expect(unsafe_code, reason = "CreateProcessWithLogonW is foreign code")]
pub fn start(
    (account, sid, password): (&str, &str, &[u16]),
    job: &Job,
    application: &[u16],
    mut line: Vec<u16>,
    env: &[u16],
) -> Result<AsAccount> {
    let user = wide(account)?;
    // `.`: the account is this machine's.
    let domain = wide(".")?;
    let handles = standard_handles();
    let mut info = STARTUPINFOW::default();
    if let Some([input, output, error]) = &handles {
        info.dwFlags = STARTF_USESTDHANDLES;
        info.hStdInput = input.0;
        info.hStdOutput = output.0;
        info.hStdError = error.0;
    }
    let Ok(size) = u32::try_from(size_of::<STARTUPINFOW>()) else {
        bail!("the start information does not fit");
    };
    info.cb = size;
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated, `line` writable as the call
    // needs, `env` a Unicode block with its double NUL; `info` and the
    // handles it names stay alive until the call returns; the current
    // directory is this process's.
    let created = unsafe {
        CreateProcessWithLogonW(
            user.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            line.as_mut_ptr(),
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            env.as_ptr().cast(),
            ptr::null(),
            &raw const info,
            &raw mut process,
        )
    };
    drop(handles);
    if created == 0 {
        bail!(
            "starting the agent as {account} (the Secondary Logon service starts it): {}",
            last_error()
        );
    }
    let started = contain(job, Owned(process.hProcess), Owned(process.hThread))?;
    let user_is_account =
        process_user(&started.process).is_some_and(|user| user.eq_ignore_ascii_case(sid));
    Ok(AsAccount {
        started,
        user_is_account,
    })
}

/// Delete the profile Windows made for the account `sid` at its first
/// logon; none is fine.
#[expect(unsafe_code, reason = "DeleteProfileW is foreign code")]
pub fn delete_profile(sid: &str) -> Result<()> {
    let sid_w = wide(sid)?;
    // SAFETY: `sid_w` is NUL-terminated; Windows finds the profile's path
    // and this machine itself.
    if unsafe { DeleteProfileW(sid_w.as_ptr(), ptr::null(), ptr::null()) } == 0 {
        let error = last_error();
        if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND.cast_signed()) {
            bail!("deleting the account's profile: {error}");
        }
    }
    Ok(())
}
