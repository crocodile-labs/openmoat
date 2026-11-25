//! The account itself (ADR-129 §1, item 1): create and delete it, take it out
//! of every local group, give and read back its logon rights, and look up
//! names and SIDs. Foreign code throughout, so this file may use `unsafe`;
//! each buffer the network management or LSA functions allocate is freed by a
//! guard on every path out.
//!
//! Microsoft's documentation of each call:
//! - `NetUserAdd` with `USER_INFO_1` and `USER_PRIV_USER`, which also makes
//!   the account a member of `Users`:
//!   <https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netuseradd>.
//! - `NetUserDel`: <https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netuserdel>.
//! - `NetUserGetLocalGroups` (`LG_INCLUDE_INDIRECT`):
//!   <https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netusergetlocalgroups>.
//! - `NetLocalGroupDelMembers` (level 0, by SID):
//!   <https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupdelmembers>.
//! - `LsaOpenPolicy`, `LsaAddAccountRights`, `LsaEnumerateAccountRights`,
//!   `LsaRemoveAccountRights` and the rights' names ("Account rights
//!   constants"):
//!   <https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights>,
//!   <https://learn.microsoft.com/windows/win32/secauthz/account-rights-constants>.
//! - `LookupAccountNameW`, `LookupAccountSidW`:
//!   <https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountnamew>.

use std::ptr;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NTSTATUS};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_MEMBERS_INFO_0, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
    NERR_Success, NERR_UserExists, NERR_UserNotFound, NetApiBufferFree, NetLocalGroupDelMembers,
    NetUserAdd, NetUserDel, NetUserGetLocalGroups, UF_DONT_EXPIRE_PASSWD, UF_PASSWD_CANT_CHANGE,
    UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
    LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
    LsaRemoveAccountRights, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, SID_NAME_USE};

use super::super::win32::{sid_from, sid_string};
use super::wide;

/// `STATUS_OBJECT_NAME_NOT_FOUND`: an account with no rights at all.
const NO_RIGHTS: NTSTATUS = 0xC000_0034_u32.cast_signed();

/// `ERROR_MEMBER_NOT_IN_ALIAS`: already out of the group.
const NOT_A_MEMBER: u32 = 1377;

/// `NERR_Success`, `NERR_UserExists` and `NERR_UserNotFound`, named so they
/// can be matched on.
const SUCCESS: u32 = NERR_Success;
const EXISTS: u32 = NERR_UserExists;
const NOT_FOUND: u32 = NERR_UserNotFound;

/// A buffer the network management functions allocated.
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    #[expect(unsafe_code, reason = "NetApiBufferFree is foreign code")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Net* call that allocates with
            // NetApiBufferAllocate; it is freed once.
            unsafe { NetApiBufferFree(self.0.cast()) };
        }
    }
}

/// Create the local account `name` with `password`: a standard user whose
/// password does not expire and cannot be changed by the account.
#[expect(unsafe_code, reason = "NetUserAdd is foreign code")]
pub fn create(name: &str, password: &[u16]) -> Result<()> {
    let mut name_w = wide(name)?;
    let mut password_w = password.to_vec();
    let mut comment = wide("OpenMoat agent account (openmoat agent-account remove deletes it)")?;
    let info = USER_INFO_1 {
        usri1_name: name_w.as_mut_ptr(),
        usri1_password: password_w.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: ptr::null_mut(),
        usri1_comment: comment.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: ptr::null_mut(),
    };
    let mut bad = 0;
    // SAFETY: every string in `info` is NUL-terminated and outlives the call.
    let status = unsafe { NetUserAdd(ptr::null(), 1, (&raw const info).cast(), &raw mut bad) };
    zeroize::Zeroize::zeroize(&mut password_w);
    match status {
        SUCCESS => Ok(()),
        EXISTS => bail!(
            "a local account named {name} exists already: `openmoat agent-account status` \
             says whether it is OpenMoat's; delete it with `net user {name} /delete` from an \
             administrator terminal if it is not yours"
        ),
        other => bail!("creating the local account {name}: Windows error {other} (field {bad})"),
    }
}

/// Delete the local account `name`; one that is gone already is fine.
#[expect(unsafe_code, reason = "NetUserDel is foreign code")]
pub fn delete(name: &str) -> Result<()> {
    let name_w = wide(name)?;
    // SAFETY: `name_w` is NUL-terminated.
    match unsafe { NetUserDel(ptr::null(), name_w.as_ptr()) } {
        SUCCESS | NOT_FOUND => Ok(()),
        other => bail!("deleting the local account {name}: Windows error {other}"),
    }
}

/// The local groups `name` is a member of, directly or through another.
#[expect(unsafe_code, reason = "NetUserGetLocalGroups is foreign code")]
pub fn local_groups(name: &str) -> Result<Vec<String>> {
    let name_w = wide(name)?;
    let mut buffer: *mut u8 = ptr::null_mut();
    let (mut read, mut total) = (0_u32, 0_u32);
    // SAFETY: `name_w` is NUL-terminated; `buffer` receives an allocated
    // array of `read` entries.
    let status = unsafe {
        NetUserGetLocalGroups(
            ptr::null(),
            name_w.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &raw mut buffer,
            MAX_PREFERRED_LENGTH,
            &raw mut read,
            &raw mut total,
        )
    };
    let buffer = NetBuffer(buffer);
    if status != SUCCESS {
        bail!("reading the local groups of {name}: Windows error {status}");
    }
    // NetApiBufferAllocate's memory is aligned for any structure.
    let entries = buffer
        .0
        .cast::<std::ffi::c_void>()
        .cast::<LOCALGROUP_USERS_INFO_0>();
    let mut groups = Vec::new();
    for index in 0..read as usize {
        // SAFETY: `index` is below the count Windows wrote; each name is a
        // NUL-terminated string inside the buffer.
        let group = unsafe { (*entries.add(index)).lgrui0_name };
        groups.push(text_of(group));
    }
    Ok(groups)
}

/// Take `sid` out of the local group whose SID is `group` (the built-in
/// `Users`, whose name differs by language); one that is out already is fine.
#[expect(unsafe_code, reason = "NetLocalGroupDelMembers is foreign code")]
pub fn leave_group(group: &str, sid: &str) -> Result<()> {
    let name = name_of(group)?;
    let name_w = wide(&name)?;
    let member_sid = sid_from(sid)?;
    let member = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: member_sid.0,
    };
    // SAFETY: `name_w` is NUL-terminated; one entry whose SID lives in
    // `member_sid` for the call.
    let status = unsafe {
        NetLocalGroupDelMembers(
            ptr::null(),
            name_w.as_ptr(),
            0,
            (&raw const member).cast(),
            1,
        )
    };
    match status {
        SUCCESS | NOT_A_MEMBER => Ok(()),
        other => bail!("taking the account out of {name}: Windows error {other}"),
    }
}

/// The text of a NUL-terminated UTF-16 string Windows wrote.
#[expect(unsafe_code, reason = "reading a string Windows wrote")]
fn text_of(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every index up to the NUL is in it.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL are initialised.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

/// The SID of the account `name` on this machine; `None` when there is none.
#[expect(unsafe_code, reason = "LookupAccountNameW is foreign code")]
pub fn sid_of(name: &str) -> Result<Option<String>> {
    let name_w = wide(name)?;
    let (mut sid_len, mut domain_len) = (0_u32, 0_u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a size query: no buffers, the sizes needed are written back.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name_w.as_ptr(),
            ptr::null_mut(),
            &raw mut sid_len,
            ptr::null_mut(),
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    let error = std::io::Error::last_os_error();
    if sid_len == 0 {
        return match error.raw_os_error() {
            // ERROR_NONE_MAPPED: no account of that name.
            Some(1332) => Ok(None),
            _ => bail!("looking up the account {name}: {error}"),
        };
    }
    let mut sid = vec![0_u64; (sid_len as usize).div_ceil(8)];
    let mut domain = vec![0_u16; domain_len as usize];
    // SAFETY: `sid` holds at least `sid_len` aligned bytes and `domain`
    // `domain_len` units, as the size query asked.
    let found = unsafe {
        LookupAccountNameW(
            ptr::null(),
            name_w.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_len,
            domain.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    if found == 0 {
        bail!(
            "looking up the account {name}: {}",
            std::io::Error::last_os_error()
        );
    }
    sid_string(sid.as_mut_ptr().cast()).map(Some)
}

/// The name of the account or group `sid`.
#[expect(unsafe_code, reason = "LookupAccountSidW is foreign code")]
pub fn name_of(sid: &str) -> Result<String> {
    let sid_w = sid_from(sid)?;
    let (mut name_len, mut domain_len) = (0_u32, 0_u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a size query: no buffers, the sizes needed are written back.
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid_w.0,
            ptr::null_mut(),
            &raw mut name_len,
            ptr::null_mut(),
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed()) || name_len == 0 {
        bail!("looking up {sid}: {error}");
    }
    let mut name = vec![0_u16; name_len as usize];
    let mut domain = vec![0_u16; domain_len as usize];
    // SAFETY: the buffers hold the sizes the query asked for.
    let found = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid_w.0,
            name.as_mut_ptr(),
            &raw mut name_len,
            domain.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    if found == 0 {
        bail!("looking up {sid}: {}", std::io::Error::last_os_error());
    }
    Ok(text_of(name.as_ptr()))
}

/// The local security policy, open for rights; closed when dropped.
struct Policy(LSA_HANDLE);

impl Drop for Policy {
    #[expect(unsafe_code, reason = "LsaClose is foreign code")]
    fn drop(&mut self) {
        // SAFETY: the handle came from LsaOpenPolicy and is closed once.
        unsafe { LsaClose(self.0) };
    }
}

/// `status` as an error naming `what`, unless it is success.
#[expect(unsafe_code, reason = "LsaNtStatusToWinError is foreign code")]
fn lsa(status: NTSTATUS, what: &str) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    // SAFETY: a pure conversion of a status code.
    let code = unsafe { LsaNtStatusToWinError(status) };
    bail!(
        "{what}: {}",
        std::io::Error::from_raw_os_error(code.cast_signed())
    )
}

#[expect(unsafe_code, reason = "LsaOpenPolicy is foreign code")]
fn open_policy(access: i32) -> Result<Policy> {
    let attributes = LSA_OBJECT_ATTRIBUTES::default();
    let mut handle: LSA_HANDLE = 0;
    // SAFETY: the local system (no name); zeroed attributes, as the call
    // asks; `handle` receives the policy's handle.
    let status = unsafe {
        LsaOpenPolicy(
            ptr::null(),
            &raw const attributes,
            access.cast_unsigned(),
            &raw mut handle,
        )
    };
    lsa(status, "opening the local security policy")?;
    Ok(Policy(handle))
}

/// `rights` as the strings the LSA calls take; `units` keeps their text.
fn lsa_strings(rights: &[&str], units: &mut Vec<Vec<u16>>) -> Result<Vec<LSA_UNICODE_STRING>> {
    *units = rights.iter().map(|r| r.encode_utf16().collect()).collect();
    units
        .iter_mut()
        .map(|text| {
            let Ok(len) = u16::try_from(text.len() * 2) else {
                bail!("a right's name is too long");
            };
            Ok(LSA_UNICODE_STRING {
                Length: len,
                MaximumLength: len,
                Buffer: text.as_mut_ptr(),
            })
        })
        .collect()
}

/// Give `sid` each of `rights` (logon rights: allow and deny).
#[expect(unsafe_code, reason = "LsaAddAccountRights is foreign code")]
pub fn add_rights(sid: &str, rights: &[&str]) -> Result<()> {
    let policy = open_policy(POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES)?;
    let account = sid_from(sid)?;
    let mut units = Vec::new();
    let strings = lsa_strings(rights, &mut units)?;
    let Ok(count) = u32::try_from(strings.len()) else {
        bail!("too many rights");
    };
    // SAFETY: the policy is open for adding; `strings` points into `units`,
    // alive for the call; the SID lives in `account`.
    let status = unsafe { LsaAddAccountRights(policy.0, account.0, strings.as_ptr(), count) };
    lsa(status, "giving the account its logon rights")
}

/// Every right `sid` holds or is denied.
#[expect(unsafe_code, reason = "LsaEnumerateAccountRights is foreign code")]
pub fn rights(sid: &str) -> Result<Vec<String>> {
    let policy = open_policy(POLICY_LOOKUP_NAMES)?;
    let account = sid_from(sid)?;
    let mut list: *mut LSA_UNICODE_STRING = ptr::null_mut();
    let mut count = 0_u32;
    // SAFETY: the policy is open for lookups; `list` receives an array of
    // `count` strings the LSA allocated.
    let status =
        unsafe { LsaEnumerateAccountRights(policy.0, account.0, &raw mut list, &raw mut count) };
    if status == NO_RIGHTS {
        return Ok(Vec::new());
    }
    lsa(status, "reading the account's logon rights")?;
    let _free = Lsa(list.cast());
    let mut out = Vec::new();
    for index in 0..count as usize {
        // SAFETY: `index` is below the count; each string's buffer holds
        // `Length` bytes.
        let text = unsafe {
            let right = &*list.add(index);
            std::slice::from_raw_parts(right.Buffer, usize::from(right.Length) / 2)
        };
        out.push(String::from_utf16_lossy(text));
    }
    Ok(out)
}

/// Take every right from `sid`, as `remove` does before deleting it.
#[expect(unsafe_code, reason = "LsaRemoveAccountRights is foreign code")]
pub fn remove_rights(sid: &str) -> Result<()> {
    let policy = open_policy(POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT)?;
    let account = sid_from(sid)?;
    // SAFETY: the policy is open; `AllRights` removes every right, and with
    // it the LSA's account object; no list is passed.
    let status = unsafe { LsaRemoveAccountRights(policy.0, account.0, true, ptr::null(), 0) };
    if status == NO_RIGHTS {
        return Ok(());
    }
    lsa(status, "taking the account's logon rights")
}

/// A buffer the LSA allocated.
struct Lsa(*mut std::ffi::c_void);

impl Drop for Lsa {
    #[expect(unsafe_code, reason = "LsaFreeMemory is foreign code")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an LSA call; it is freed once.
            unsafe { LsaFreeMemory(self.0) };
        }
    }
}
