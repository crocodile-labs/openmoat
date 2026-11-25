//! The Win32 calls behind `openmoat run` on Windows (ADR-115): the
//! write-restricted token, the job object, starting the agent suspended under
//! both (the access-list entries are in `acl.rs`, the agent account's calls
//! in `account/`). Every call here is foreign code. Each handle is
//! closed by an [`Owned`] guard and each buffer Windows allocates freed by a
//! [`Local`] guard, on every path out.
//!
//! Microsoft's documentation of each call:
//! - `CreateRestrictedToken` (`WRITE_RESTRICTED`, `DISABLE_MAX_PRIVILEGE`):
//!   <https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken>,
//!   and how restricted SIDs enter an access check:
//!   <https://learn.microsoft.com/windows/win32/secauthz/restricted-tokens>.
//! - `CreateProcessAsUserW`, which takes "a restricted version of the
//!   caller's primary token" without `SE_ASSIGNPRIMARYTOKEN_NAME`:
//!   <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw>.
//! - Job objects and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`:
//!   <https://learn.microsoft.com/windows/win32/procthread/job-objects>,
//!   <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information>.
//! - `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so the agent inherits its three
//!   standard handles and nothing else this process holds:
//!   <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle as _;
use std::ptr::{self, addr_of};

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_ALL, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, CreateRestrictedToken,
    DISABLE_MAX_PRIVILEGE, GetLengthSid, GetTokenInformation, InitializeAcl, IsTokenRestricted,
    PSID, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenUser, WRITE_RESTRICTED,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::sandbox::write_token::objects_sid;

/// Everyone (`S-1-1-0`): among the restricting SIDs, as in Codex's Windows
/// sandbox, so that writing `NUL` and the like works.
const EVERYONE: &str = "S-1-1-0";

/// `SYSTEM`.
const SYSTEM: &str = "S-1-5-18";

/// `SE_GROUP_LOGON_ID`: the group of a token that is its logon session's SID.
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

/// A handle this process owns, closed when dropped.
pub struct Owned(pub(super) HANDLE);

impl Drop for Owned {
    #[expect(unsafe_code, reason = "CloseHandle is foreign code")]
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle came from a Win32 call that gave this
            // process ownership of it, and it is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// A buffer Windows allocated with `LocalAlloc`, freed when dropped.
pub(super) struct Local(pub(super) *mut c_void);

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

pub(super) fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// A SID from its string, freed when the guard drops.
#[expect(unsafe_code, reason = "ConvertStringSidToSidW is foreign code")]
pub(super) fn sid_from(text: &str) -> Result<Local> {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `sid` receives a LocalAlloc'd SID.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 {
        bail!("reading the SID {text}: {}", last_error());
    }
    Ok(Local(sid))
}

/// `sid` as a string (`S-1-5-21-…`).
#[expect(unsafe_code, reason = "ConvertSidToStringSidW is foreign code")]
pub(super) fn sid_string(sid: PSID) -> Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` points at a valid SID that outlives this call; `text`
    // receives a LocalAlloc'd, NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        bail!("reading a SID: {}", last_error());
    }
    let _free = Local(text.cast());
    let mut len = 0;
    // SAFETY: `text` is NUL-terminated, so every index up to the NUL is in it.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL are initialised and stay alive
    // until `_free` drops at the end of this function.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    Ok(String::from_utf16_lossy(units))
}

/// `class` of `token`, in a buffer of u64s so that it is aligned for every
/// structure Windows writes there.
#[expect(unsafe_code, reason = "GetTokenInformation is foreign code")]
pub(super) fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>> {
    let mut len: u32 = 0;
    // SAFETY: a size query: no buffer, the size needed is written to `len`.
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut len) };
    if len == 0 {
        bail!("reading this process's token: {}", last_error());
    }
    let mut buffer = vec![0_u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `len` writable bytes.
    let filled =
        unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &raw mut len) };
    if filled == 0 {
        bail!("reading this process's token: {}", last_error());
    }
    Ok(buffer)
}

/// The account of `token`.
#[expect(unsafe_code, reason = "reading TOKEN_USER that Windows wrote")]
pub(super) fn user_sid(token: HANDLE) -> Result<String> {
    let buffer = token_info(token, TokenUser)?;
    // SAFETY: GetTokenInformation wrote a TOKEN_USER at the start of the
    // 8-byte aligned `buffer`; its SID points into `buffer`, alive here.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

/// The logon session's SID of `token`, when it has one.
#[expect(unsafe_code, reason = "reading TOKEN_GROUPS that Windows wrote")]
fn logon_sid(token: HANDLE) -> Result<Option<String>> {
    let buffer = token_info(token, TokenGroups)?;
    let groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: GetTokenInformation wrote a TOKEN_GROUPS at the start of the
    // aligned `buffer`: its count, then that many SID_AND_ATTRIBUTES, all
    // inside `buffer`.
    let count = unsafe { ptr::read(addr_of!((*groups).GroupCount)) };
    // SAFETY: as above; the array starts at `Groups`.
    let first = unsafe { addr_of!((*groups).Groups) }.cast::<SID_AND_ATTRIBUTES>();
    for index in 0..count as usize {
        // SAFETY: `index` is below the count Windows wrote.
        let group = unsafe { &*first.add(index) };
        if group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            return sid_string(group.Sid).map(Some);
        }
    }
    Ok(None)
}

/// An ACL granting `GENERIC_ALL` to each of `sids`, in a buffer that is the ACL.
#[expect(unsafe_code, reason = "ACL building is foreign code")]
fn allow_all(sids: &[Local]) -> Result<Vec<u32>> {
    let mut size = size_of::<ACL>();
    for sid in sids {
        // SAFETY: `sid.0` is a valid SID from ConvertStringSidToSidW.
        let len = unsafe { GetLengthSid(sid.0) } as usize;
        size += size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + len;
    }
    // u32s: an ACL must be DWORD-aligned
    let mut buffer = vec![0_u32; size.div_ceil(4)];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    let Ok(acl_size) = u32::try_from(buffer.len() * 4) else {
        bail!("the access list would be too large");
    };
    // SAFETY: `buffer` holds `acl_size` writable, DWORD-aligned bytes.
    if unsafe { InitializeAcl(acl, acl_size, ACL_REVISION) } == 0 {
        bail!("making the token's default access list: {}", last_error());
    }
    for sid in sids {
        // SAFETY: `acl` was initialised with room for every entry; `sid.0`
        // is a valid SID.
        if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid.0) } == 0 {
            bail!(
                "adding to the token's default access list: {}",
                last_error()
            );
        }
    }
    Ok(buffer)
}

/// A primary token like this process's, without its privileges (but
/// `SeChangeNotifyPrivilege`), whose writes also need one of `Everyone`, the
/// logon session's SID, [`objects_sid`] or `roots` granted. Its default
/// access list, which the objects the agent creates get, grants the account,
/// `SYSTEM` and [`objects_sid`], so the agent can write its own pipes.
#[expect(unsafe_code, reason = "token calls are foreign code")]
pub fn restricted_token(roots: &[String]) -> Result<Owned> {
    let mut token: HANDLE = ptr::null_mut();
    let access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `token` receives a handle this process owns.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) } == 0 {
        bail!("opening this process's token: {}", last_error());
    }
    let token = Owned(token);
    let objects = objects_sid();
    let mut names = vec![EVERYONE.to_owned()];
    names.extend(logon_sid(token.0)?);
    names.push(objects.clone());
    names.extend(roots.iter().cloned());
    let sids = names
        .iter()
        .map(|name| sid_from(name))
        .collect::<Result<Vec<Local>>>()?;
    let restricting: Vec<SID_AND_ATTRIBUTES> = sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: 0,
        })
        .collect();
    let Ok(count) = u32::try_from(restricting.len()) else {
        bail!("too many write roots");
    };
    let mut restricted: HANDLE = ptr::null_mut();
    // SAFETY: `token` is open with TOKEN_DUPLICATE; `restricting` holds
    // `count` entries whose SIDs live in `sids` until after the call; no SID
    // is disabled and no privilege listed (DISABLE_MAX_PRIVILEGE drops them).
    let made = unsafe {
        CreateRestrictedToken(
            token.0,
            DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
            0,
            ptr::null(),
            0,
            ptr::null(),
            count,
            restricting.as_ptr(),
            &raw mut restricted,
        )
    };
    if made == 0 {
        bail!("making the write-restricted token: {}", last_error());
    }
    let restricted = Owned(restricted);
    let owners = [user_sid(token.0)?, SYSTEM.to_owned(), objects];
    let owners = owners
        .iter()
        .map(|name| sid_from(name))
        .collect::<Result<Vec<Local>>>()?;
    let mut acl = allow_all(&owners)?;
    let default = TOKEN_DEFAULT_DACL {
        DefaultDacl: acl.as_mut_ptr().cast(),
    };
    let Ok(len) = u32::try_from(size_of::<TOKEN_DEFAULT_DACL>()) else {
        bail!("the default access list does not fit");
    };
    // SAFETY: the new token has the access of the handle it came from,
    // TOKEN_ADJUST_DEFAULT included; `default` points at a valid ACL in
    // `acl`, which outlives the call (Windows copies it).
    let set = unsafe {
        SetTokenInformation(
            restricted.0,
            TokenDefaultDacl,
            (&raw const default).cast(),
            len,
        )
    };
    if set == 0 {
        bail!("setting the token's default access list: {}", last_error());
    }
    Ok(restricted)
}

/// Whether the token of the process `process` is restricted.
#[expect(unsafe_code, reason = "token calls are foreign code")]
fn token_restricted(process: HANDLE) -> bool {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process` is a process handle this process holds (or the
    // current-process pseudo-handle); `token` receives a handle it owns.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let token = Owned(token);
    // SAFETY: `token` is open with TOKEN_QUERY.
    unsafe { IsTokenRestricted(token.0) != 0 }
}

/// Whether this process runs under a restricted token.
#[expect(unsafe_code, reason = "GetCurrentProcess is foreign code")]
pub fn current_token_restricted() -> bool {
    // SAFETY: a pseudo-handle that needs no closing.
    token_restricted(unsafe { GetCurrentProcess() })
}

/// A job object whose processes all end when its last handle closes, and
/// from which no process may break away.
pub struct Job(pub(super) Owned);

impl Job {
    #[expect(unsafe_code, reason = "job object calls are foreign code")]
    pub fn new() -> Result<Self> {
        // SAFETY: no attributes and no name: a new, unnamed job.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            bail!("creating a job object: {}", last_error());
        }
        let job = Self(Owned(handle));
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // No JOB_OBJECT_LIMIT_BREAKAWAY_OK: a child asking to leave is refused.
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        let Ok(len) = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()) else {
            bail!("the job's limits do not fit");
        };
        // SAFETY: `limits` is a valid structure of the class named, `len`
        // bytes long, alive for the call.
        let set = unsafe {
            SetInformationJobObject(
                job.0.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                len,
            )
        };
        if set == 0 {
            bail!("setting the job's limits: {}", last_error());
        }
        Ok(job)
    }

    /// End every process in the job.
    #[expect(unsafe_code, reason = "TerminateJobObject is foreign code")]
    pub fn terminate(&self) {
        // SAFETY: the job handle is open; ending an empty job does nothing.
        unsafe { TerminateJobObject(self.0.0, 1) };
    }
}

/// An attribute list Windows initialised, deleted when dropped.
struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _buffer: Vec<u64>,
}

impl Drop for Attributes {
    #[expect(unsafe_code, reason = "DeleteProcThreadAttributeList is foreign code")]
    fn drop(&mut self) {
        // SAFETY: `list` was initialised by InitializeProcThreadAttributeList
        // in `_buffer`, which is still alive; it is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

/// Inheritable copies of this process's standard input, output and error;
/// `None` when one is missing or cannot be copied, and the agent then gets
/// the console's own.
#[expect(unsafe_code, reason = "DuplicateHandle is foreign code")]
pub(super) fn standard_handles() -> Option<[Owned; 3]> {
    let streams = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    let mut copies = Vec::with_capacity(3);
    for stream in streams {
        if stream.is_null() || stream == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut copy: HANDLE = ptr::null_mut();
        // SAFETY: `stream` is a handle of this process (its standard
        // stream); the copy, inheritable, is this process's to close.
        let duplicated = unsafe {
            let me = GetCurrentProcess();
            DuplicateHandle(me, stream, me, &raw mut copy, 0, 1, DUPLICATE_SAME_ACCESS)
        };
        if duplicated == 0 {
            return None;
        }
        copies.push(Owned(copy));
    }
    copies.try_into().ok()
}

/// An attribute list whose one attribute is `handles`, the only handles the
/// agent inherits.
#[expect(unsafe_code, reason = "attribute list calls are foreign code")]
fn handle_list(handles: &[HANDLE]) -> Result<Attributes> {
    let mut size = 0_usize;
    // SAFETY: a size query: no list, the size needed is written to `size`.
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut size) };
    if size == 0 {
        bail!("sizing the start attributes: {}", last_error());
    }
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = buffer.as_mut_ptr().cast();
    // SAFETY: `buffer` holds at least `size` writable, aligned bytes.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &raw mut size) } == 0 {
        bail!("making the start attributes: {}", last_error());
    }
    let attributes = Attributes {
        list,
        _buffer: buffer,
    };
    // SAFETY: `list` is initialised for one attribute; `handles` is a slice
    // of inheritable handles that the caller keeps alive until the process
    // is created, as UpdateProcThreadAttribute requires.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            attributes.list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of_val(handles),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if updated == 0 {
        bail!("listing the handles the agent inherits: {}", last_error());
    }
    Ok(attributes)
}

/// The agent, created suspended in the job: nothing of it has run yet.
pub struct Started {
    pub(super) process: Owned,
    pub(super) thread: Owned,
    /// The agent's own token, read back, is restricted.
    pub token_restricted: bool,
    /// The agent's process, read back, is in the job.
    pub in_job: bool,
}

/// Put the suspended `process` (with its first `thread`) in `job` and read
/// its membership back; a process that cannot be put in the job is ended
/// before it runs.
#[expect(unsafe_code, reason = "job object calls are foreign code")]
pub(super) fn contain(job: &Job, process: Owned, thread: Owned) -> Result<Started> {
    let started = Started {
        process,
        thread,
        token_restricted: false,
        in_job: false,
    };
    // SAFETY: both handles are open; the process has not run.
    if unsafe { AssignProcessToJobObject(job.0.0, started.process.0) } == 0 {
        let error = last_error();
        // SAFETY: the process handle is open, with every right.
        unsafe { TerminateProcess(started.process.0, 1) };
        bail!("putting the agent in its job object: {error}");
    }
    let mut in_job = 0;
    // SAFETY: both handles are open; `in_job` receives the answer.
    let asked = unsafe { IsProcessInJob(started.process.0, job.0.0, &raw mut in_job) };
    Ok(Started {
        in_job: asked != 0 && in_job != 0,
        ..started
    })
}

/// Create `application` with command line `line` and environment block
/// `env` under `token`, suspended, inheriting only its standard handles, and
/// put it in `job`; read its token and job back. A process that cannot be
/// put in the job is ended before it runs.
#[expect(unsafe_code, reason = "process creation is foreign code")]
pub fn start(
    token: &Owned,
    job: &Job,
    application: &[u16],
    mut line: Vec<u16>,
    env: &[u16],
) -> Result<Started> {
    let handles = standard_handles();
    let raw: Vec<HANDLE> = handles.iter().flatten().map(|h| h.0).collect();
    let attributes = if raw.is_empty() {
        None
    } else {
        Some(handle_list(&raw)?)
    };
    let mut info = STARTUPINFOEXW::default();
    let mut flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    let size = if let (Some(attributes), [input, output, error]) = (&attributes, raw.as_slice()) {
        info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        info.StartupInfo.hStdInput = *input;
        info.StartupInfo.hStdOutput = *output;
        info.StartupInfo.hStdError = *error;
        info.lpAttributeList = attributes.list;
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        size_of::<STARTUPINFOEXW>()
    } else {
        size_of::<STARTUPINFOW>()
    };
    let Ok(size) = u32::try_from(size) else {
        bail!("the start information does not fit");
    };
    info.StartupInfo.cb = size;
    let inherit = i32::from(attributes.is_some());
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: `application` and `env` are NUL-terminated (the block with its
    // double NUL), `line` is NUL-terminated and writable as the call needs;
    // `info` starts with the STARTUPINFOW the flags describe and its list
    // and handles stay alive until the call returns; the current directory
    // is this process's.
    let created = unsafe {
        CreateProcessAsUserW(
            token.0,
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            inherit,
            flags,
            env.as_ptr().cast(),
            ptr::null(),
            (&raw const info).cast::<STARTUPINFOW>(),
            &raw mut process,
        )
    };
    if created == 0 {
        bail!("starting the agent under its token: {}", last_error());
    }
    let started = contain(job, Owned(process.hProcess), Owned(process.hThread))?;
    Ok(Started {
        token_restricted: token_restricted(started.process.0),
        ..started
    })
}

impl Started {
    /// Let the agent run.
    #[expect(unsafe_code, reason = "ResumeThread is foreign code")]
    pub fn resume(&self) -> Result<()> {
        // SAFETY: the thread handle is open; it was created suspended.
        if unsafe { ResumeThread(self.thread.0) } == u32::MAX {
            bail!("letting the agent run: {}", last_error());
        }
        Ok(())
    }

    /// Wait for the agent to end; its exit code.
    #[expect(unsafe_code, reason = "wait calls are foreign code")]
    pub fn wait(&self) -> Result<u32> {
        // SAFETY: the process handle is open.
        if unsafe { WaitForSingleObject(self.process.0, INFINITE) } != WAIT_OBJECT_0 {
            bail!("waiting for the agent: {}", last_error());
        }
        let mut code = 0;
        // SAFETY: the process handle is open; `code` receives its exit code.
        if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
            bail!("reading the agent's exit code: {}", last_error());
        }
        Ok(code)
    }
}
