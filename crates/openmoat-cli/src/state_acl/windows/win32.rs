//! The Win32 calls behind the state directory's access list (ADR-083): this
//! process's account, a folder's owner and DACL, and a new DACL of exactly
//! two entries. The only file of the state-directory code with `unsafe`:
//! every Win32 call is foreign code. Each buffer Windows allocates is freed
//! by a [`Local`] guard and the token handle closed by a [`Handle`] guard, on
//! every path out.
//!
//! Paths come in as NUL-terminated UTF-16 (`windows.rs` makes them).

use std::ffi::c_void;
use std::ptr::{self, addr_of};

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, IsValidAcl, IsValidSid,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::state_acl::{Descriptor, RawAce, SYSTEM};

/// Full control of a file or folder (`FILE_ALL_ACCESS`).
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// The ACE types whose body is a mask and a SID (`ACCESS_ALLOWED_ACE`,
/// `ACCESS_DENIED_ACE`).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// A buffer Windows allocated with `LocalAlloc`, freed when dropped.
struct Local(*mut c_void);

impl Drop for Local {
    #[expect(unsafe_code, reason = "LocalFree is foreign code")]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Win32 call that allocates with
            // LocalAlloc and hands ownership to the caller; it is freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A handle this process opened, closed when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    #[expect(unsafe_code, reason = "CloseHandle is foreign code")]
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The last Win32 error, for a message.
fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// `sid` as a string (`S-1-5-21-…`).
#[expect(unsafe_code, reason = "ConvertSidToStringSidW is foreign code")]
fn sid_string(sid: PSID) -> Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` points at a valid SID Windows returned and that outlives
    // this call; `text` receives a LocalAlloc'd, NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        bail!("reading a SID: {}", last_error());
    }
    let _free = Local(text.cast());
    let mut len = 0;
    // SAFETY: `text` is NUL-terminated, so every index up to the NUL is in
    // the string.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL are initialised and stay alive
    // until `_free` drops at the end of this function.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    Ok(String::from_utf16_lossy(units))
}

/// The SID of the account this process runs as.
#[expect(unsafe_code, reason = "token calls are foreign code")]
pub(super) fn current_sid() -> Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `token` receives a handle this process owns.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        bail!("opening this process's token: {}", last_error());
    }
    let token = Handle(token);
    let mut len: u32 = 0;
    // SAFETY: a size query: no buffer, the size needed is written to `len`.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut len) };
    if len == 0 {
        bail!("reading this process's account: {}", last_error());
    }
    // u64s, so the buffer is aligned for TOKEN_USER and the SID after it
    let mut buffer = vec![0_u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `len` writable bytes.
    let filled = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    };
    if filled == 0 {
        bail!("reading this process's account: {}", last_error());
    }
    // SAFETY: the call wrote a TOKEN_USER at the start of `buffer`, which is
    // 8-byte aligned; its SID points into `buffer`, alive until we return.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

/// The owner and DACL of the folder at `path` (NUL-terminated UTF-16).
#[expect(unsafe_code, reason = "security descriptor calls are foreign code")]
pub(super) fn read(path: &[u16]) -> Result<Descriptor> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; the out pointers receive pointers
    // into one LocalAlloc'd security descriptor, which `_free` frees.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("reading the access list: Windows error {status}");
    }
    let _free = Local(descriptor);
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: `descriptor` is the valid descriptor returned above.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        bail!("reading the access list's flags: {}", last_error());
    }
    let owner = if owner.is_null() {
        String::new()
    } else {
        sid_string(owner)?
    };
    let aces = if dacl.is_null() {
        None
    } else {
        Some(entries(dacl)?)
    };
    Ok(Descriptor {
        owner,
        protected: control & SE_DACL_PROTECTED != 0,
        aces,
    })
}

/// The entries of `dacl`, a DACL inside a descriptor that is alive while
/// this runs. An entry of a type without a plain mask and SID is an error.
#[expect(unsafe_code, reason = "ACL walking is foreign memory")]
fn entries(dacl: *mut ACL) -> Result<Vec<RawAce>> {
    if dacl.is_null() {
        bail!("the access list could not be read");
    }
    // SAFETY: `dacl` is non-null and points into the descriptor
    // GetNamedSecurityInfoW returned, which the caller keeps alive;
    // IsValidAcl only reads it.
    if unsafe { IsValidAcl(dacl) } == 0 {
        bail!("the access list Windows returned is not valid");
    }
    // SAFETY: `dacl` is a non-null ACL that IsValidAcl accepted; the read is
    // unaligned-safe.
    let count = unsafe { ptr::read_unaligned(addr_of!((*dacl).AceCount)) };
    let mut aces = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut slot = std::mem::MaybeUninit::<*mut c_void>::uninit();
        // SAFETY: `index` is below the ACL's AceCount; GetAce writes a pointer
        // into the ACL to `slot` when it succeeds.
        if unsafe { GetAce(dacl, index, slot.as_mut_ptr()) } == 0 {
            bail!("reading entry {index} of the access list: {}", last_error());
        }
        // SAFETY: GetAce succeeded, so it wrote `slot`.
        let ace = unsafe { slot.assume_init() };
        if ace.is_null() {
            bail!("entry {index} of the access list could not be read");
        }
        // SAFETY: `ace` is non-null and points into the ACL that IsValidAcl
        // accepted; every ACE starts with an ACE_HEADER.
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let allows = match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => true,
            ACCESS_DENIED_ACE_TYPE => false,
            other => bail!("entry {index} of the access list is of a kind not read here ({other})"),
        };
        // Allowed and denied entries share ACCESS_ALLOWED_ACE's layout: the
        // header, the mask, then the SID. The entry must hold at least that
        // much (a SID is at least 8 bytes) before any of it is read.
        let least = std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>() + 8;
        if usize::from(header.AceSize) < least {
            bail!("entry {index} of the access list is too short to hold a SID");
        }
        let body = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: an allowed or denied ACE holds at least the header, the
        // mask and a SID, all inside the ACL.
        let mask = unsafe { ptr::read_unaligned(addr_of!((*body).Mask)) };
        // SAFETY: as above; the SID starts at `SidStart`.
        let sid = unsafe { addr_of!((*body).SidStart) }
            .cast_mut()
            .cast::<c_void>();
        // SAFETY: `sid` points inside the entry, which is long enough to hold
        // a SID's fixed part; IsValidSid only reads it.
        if unsafe { IsValidSid(sid) } == 0 {
            bail!("entry {index} of the access list holds no valid SID");
        }
        aces.push(RawAce {
            allows,
            flags: header.AceFlags,
            mask,
            sid: sid_string(sid)?,
        });
    }
    Ok(aces)
}

/// A SID from its string, freed when the guard drops.
#[expect(unsafe_code, reason = "ConvertStringSidToSidW is foreign code")]
fn sid_from(text: &str) -> Result<Local> {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `sid` receives a LocalAlloc'd SID.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 {
        bail!("reading the SID {text}: {}", last_error());
    }
    Ok(Local(sid))
}

/// Give the folder at `path` a DACL of exactly two entries, full control for
/// `me` and `SYSTEM`, both handed on to what is created inside, with
/// inheritance off. Windows hands the change on to what is already inside.
#[expect(
    unsafe_code,
    reason = "ACL building and SetNamedSecurityInfoW are foreign code"
)]
pub(super) fn set_two(path: &[u16], me: &str) -> Result<()> {
    let sids = [sid_from(me)?, sid_from(SYSTEM)?];
    // the ACL header, then per entry the ACE without its first SID u32, and the SID
    let mut size = std::mem::size_of::<ACL>();
    for sid in &sids {
        // SAFETY: `sid.0` is a valid SID from ConvertStringSidToSidW.
        let len = unsafe { GetLengthSid(sid.0) } as usize;
        size += std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>() + len;
    }
    // u32s: an ACL must be DWORD-aligned
    let mut buffer = vec![0_u32; size.div_ceil(4)];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    let Ok(acl_size) = u32::try_from(buffer.len() * 4) else {
        bail!("the access list would be too large");
    };
    // SAFETY: `buffer` holds `acl_size` writable, DWORD-aligned bytes.
    if unsafe { InitializeAcl(acl, acl_size, ACL_REVISION) } == 0 {
        bail!("making the access list: {}", last_error());
    }
    for sid in &sids {
        // SAFETY: `acl` was initialised with room for both entries; `sid.0`
        // is a valid SID.
        let added = unsafe {
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid.0,
            )
        };
        if added == 0 {
            bail!("adding an entry to the access list: {}", last_error());
        }
    }
    // SAFETY: `path` is NUL-terminated and `acl` a valid ACL that outlives
    // the call; no owner, group or SACL is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("setting the access list: Windows error {status}");
    }
    Ok(())
}
