//! The access-list entries the Windows tier sets and takes out, for the
//! run's SIDs (ADR-115) and the agent account (ADR-129): [`add_entry`] adds
//! one, and [`remove`] rebuilds a list without the entries set on the place
//! itself that name a SID and match, what a run's reconciliation (a read deny
//! it no longer needs) and `openmoat agent-account remove` do. Every other
//! entry stays, in order, and the list keeps whether it inherits from its
//! folder. Foreign code, so this file may use `unsafe`.
//!
//! Microsoft's documentation: `GetNamedSecurityInfoW`, `SetEntriesInAclW`,
//! `GetAce`, `AddAce`, `InitializeAcl`, `SetNamedSecurityInfoW`, and the
//! layout every `ACCESS_ALLOWED_ACE`/`ACCESS_DENIED_ACE` shares (header,
//! mask, SID):
//! <https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setentriesinaclw>,
//! <https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace>,
//! <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-access_allowed_ace>.

use std::mem::MaybeUninit;
use std::ptr;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AddAce, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, InitializeAcl, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, UNPROTECTED_DACL_SECURITY_INFORMATION,
};

use super::win32::{Local, last_error, sid_from};

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE`.
const ALLOWED: u8 = 0;
const DENIED: u8 = 1;

/// `INHERITED_ACE`: an entry Windows handed down, not one set on the place.
const INHERITED: u8 = 0x10;

/// The mask of the allowed or denied entry at `ace`.
#[expect(unsafe_code, reason = "reading an entry Windows wrote")]
fn mask_of(ace: *const core::ffi::c_void) -> u32 {
    // SAFETY: allowed and denied entries share ACCESS_ALLOWED_ACE's layout,
    // and `ace` points at one inside a valid list.
    unsafe { (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask }
}

/// Whether the allowed or denied entry at `ace` names `sid`.
#[expect(unsafe_code, reason = "reading an entry Windows wrote")]
fn names(ace: *const core::ffi::c_void, sid: windows_sys::Win32::Security::PSID) -> bool {
    // SAFETY: as in `mask_of`; the entry's SID starts at `SidStart` and lies
    // inside the entry; `sid` is a valid SID.
    unsafe {
        let start = &raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart;
        EqualSid(start.cast_mut().cast(), sid) != 0
    }
}

/// Take out of the list of `path` (NUL-terminated UTF-16) each entry set on
/// it that names `sid` and for which `matches(allows, mask)` holds. A place
/// that is gone has nothing to take out. Returns how many were taken.
#[expect(unsafe_code, reason = "access list calls are foreign code")]
pub fn remove(path: &[u16], sid: &str, matches: &dyn Fn(bool, u32) -> bool) -> Result<usize> {
    let sid = sid_from(sid)?;
    // Written by the call before it is read: never a null this code made.
    let mut dacl = MaybeUninit::<*mut ACL>::uninit();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; `dacl` points into the LocalAlloc'd
    // descriptor, which `_descriptor` frees after the last use of `dacl`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl.as_mut_ptr(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(0);
    }
    if status != ERROR_SUCCESS {
        bail!("reading the access list: Windows error {status}");
    }
    let _descriptor = Local(descriptor);
    // SAFETY: the call succeeded, so it wrote the list's address (or null).
    let dacl = unsafe { dacl.assume_init() };
    if dacl.is_null() {
        return Ok(0);
    }
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: `descriptor` is the valid descriptor returned above.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        bail!("reading the access list's flags: {}", last_error());
    }
    // SAFETY: `dacl` is the valid list inside the descriptor.
    let (acl_revision, size, count) =
        unsafe { ((*dacl).AclRevision, (*dacl).AclSize, (*dacl).AceCount) };
    // u32s: an ACL must be DWORD-aligned; the old list's size is enough.
    let mut buffer = vec![0_u32; usize::from(size).div_ceil(4).max(2)];
    let rebuilt = buffer.as_mut_ptr().cast::<ACL>();
    let Ok(rebuilt_size) = u32::try_from(buffer.len() * 4) else {
        bail!("the access list is too large");
    };
    // SAFETY: `buffer` holds `rebuilt_size` writable, DWORD-aligned bytes.
    if unsafe { InitializeAcl(rebuilt, rebuilt_size, u32::from(acl_revision)) } == 0 {
        bail!("making the access list: {}", last_error());
    }
    let mut taken = 0;
    for index in 0..u32::from(count) {
        let mut ace = MaybeUninit::<*mut core::ffi::c_void>::uninit();
        // SAFETY: `index` is below the list's count.
        if unsafe { GetAce(dacl, index, ace.as_mut_ptr()) } == 0 {
            bail!("reading an access list entry: {}", last_error());
        }
        // SAFETY: the call succeeded, so it wrote the entry's address.
        let ace = unsafe { ace.assume_init() };
        // SAFETY: every entry starts with an ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let explicit =
            matches!(header.AceType, ALLOWED | DENIED) && header.AceFlags & INHERITED == 0;
        if explicit && names(ace, sid.0) && matches(header.AceType == ALLOWED, mask_of(ace)) {
            taken += 1;
            continue;
        }
        // SAFETY: `rebuilt` has room for every entry of the old list; the
        // entry is `AceSize` bytes at `ace`; u32::MAX appends it.
        let added = unsafe {
            AddAce(
                rebuilt,
                u32::from(acl_revision),
                u32::MAX,
                ace,
                u32::from(header.AceSize),
            )
        };
        if added == 0 {
            bail!("copying an access list entry: {}", last_error());
        }
    }
    if taken == 0 {
        return Ok(0);
    }
    let protection = if control & SE_DACL_PROTECTED == 0 {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    } else {
        PROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: `path` is NUL-terminated and `rebuilt` a valid ACL that
    // outlives the call; no owner, group or SACL is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            rebuilt,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("setting the access list: Windows error {status}");
    }
    Ok(taken)
}

/// Add one entry for `sid` to the access list of `path` (NUL-terminated
/// UTF-16): `allows` or denies `mask`, handed to everything below when
/// `inherit`. The list keeps every entry it had, and whether it inherits
/// from its folder.
#[expect(unsafe_code, reason = "access list calls are foreign code")]
pub fn add_entry(
    path: &[u16],
    sid: &str,
    (allows, mask, inherit): (bool, u32, bool),
) -> Result<()> {
    let sid = sid_from(sid)?;
    // Written by the call before it is read: never a null this code made.
    let mut dacl = MaybeUninit::<*mut ACL>::uninit();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; `dacl` points into the LocalAlloc'd
    // descriptor, which `_descriptor` frees after the last use of `dacl`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl.as_mut_ptr(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("reading the access list: Windows error {status}");
    }
    let _descriptor = Local(descriptor);
    // SAFETY: the call succeeded, so it wrote the list's address (or null).
    let dacl = unsafe { dacl.assume_init() };
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: `descriptor` is the valid descriptor returned above.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        bail!("reading the access list's flags: {}", last_error());
    }
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: if allows { GRANT_ACCESS } else { DENY_ACCESS },
        grfInheritance: if inherit {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.0.cast(),
        },
    };
    let mut merged: *mut ACL = ptr::null_mut();
    // SAFETY: one entry, whose SID lives in `sid`; `dacl` is the current list
    // (or null); `merged` receives a LocalAlloc'd list.
    let status = unsafe { SetEntriesInAclW(1, &raw const access, dacl, &raw mut merged) };
    if status != ERROR_SUCCESS {
        bail!("adding the entry: Windows error {status}");
    }
    let _merged = Local(merged.cast());
    let protection = if control & SE_DACL_PROTECTED == 0 {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    } else {
        PROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: `path` is NUL-terminated and `merged` a valid ACL that
    // outlives the call; no owner, group or SACL is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            merged,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("setting the access list: Windows error {status}");
    }
    Ok(())
}
