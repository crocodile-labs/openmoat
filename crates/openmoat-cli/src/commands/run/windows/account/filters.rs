//! The agent account's network filters in the Windows Filtering Platform
//! (ADR-129 §1 item 4): installed by `openmoat agent-account setup`, read
//! back by `status` and by every run, deleted by `remove`. What they are is
//! decided in `crate::agent_account::wfp`; this file makes the calls.
//! Foreign code, so this file may use `unsafe`. Installing and deleting each
//! happen in one WFP transaction, so a step that fails leaves nothing of
//! that call behind; what the engine allocates is freed by a guard.
//!
//! Microsoft's documentation:
//! - `FwpmEngineOpen0` (no session given: the objects outlive the handle)
//!   and `FwpmEngineClose0`:
//!   <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0>.
//! - `FwpmTransactionBegin0`, `FwpmTransactionCommit0`,
//!   `FwpmTransactionAbort0`:
//!   <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0>.
//! - `FwpmProviderAdd0` (`FWPM_PROVIDER_FLAG_PERSISTENT`), `FwpmSubLayerAdd0`
//!   (`FWPM_SUBLAYER_FLAG_PERSISTENT`), `FwpmFilterAdd0`
//!   (`FWPM_FILTER_FLAG_PERSISTENT`; `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, a
//!   block a sublayer of lower weight cannot override):
//!   <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0>,
//!   <https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0>.
//! - `FWPM_CONDITION_ALE_USER_ID` takes a security descriptor
//!   (`FWP_SECURITY_DESCRIPTOR_TYPE`) whose access check is made against the
//!   connecting application's token; `D:(A;;CC;;;<SID>)` grants the
//!   account's SID `FWP_ACTRL_MATCH_FILTER`:
//!   <https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers->.
//! - `FwpmFilterGetByKey0`, `FwpmProviderGetByKey0`, `FwpmSubLayerGetByKey0`,
//!   each freed with `FwpmFreeMemory0`; the `*DeleteByKey0` calls:
//!   <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0>.

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{
    FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE,
    FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_LISTEN_V4,
    FWPM_LAYER_ALE_AUTH_LISTEN_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use super::super::win32::Local;
use super::wide;
use crate::agent_account::wfp::{self, Facts, Filter, Layer, Seen, Wfp};

/// The name every object of OpenMoat's in the engine carries.
const NAME: &str = "OpenMoat agent account";

/// What `netsh wfp show filters` and other tools show beside it.
const DESCRIPTION: &str = "Holds the network of OpenMoat's Windows agent account to OpenMoat's \
     proxy on loopback (openmoat agent-account, ADR-129)";

/// The sublayer's weight: of the highest, so its hard blocks are weighed
/// before the sublayers other software adds.
const SUBLAYER_WEIGHT: u16 = u16::MAX;

/// Within the sublayer the permit outweighs the block, so a connection to
/// the proxy's ports on loopback is permitted and every other one blocked.
const PERMIT_WEIGHT: u8 = 15;
const BLOCK_WEIGHT: u8 = 1;

/// `code` as an error naming `what`; success is 0.
fn check(code: u32, what: &str) -> Result<()> {
    if code != 0 {
        bail!(
            "{what}: error 0x{code:08X} ({})",
            std::io::Error::from_raw_os_error(code.cast_signed())
        );
    }
    Ok(())
}

/// `text` (a key of the record) as the engine's GUID.
fn guid(text: &str) -> Result<GUID> {
    Ok(GUID::from_u128(wfp::parse_key(text)?))
}

/// `key` as the record's text.
fn text(key: &GUID) -> String {
    let value = (u128::from(key.data1) << 96)
        | (u128::from(key.data2) << 80)
        | (u128::from(key.data3) << 64)
        | u128::from(u64::from_be_bytes(key.data4));
    wfp::key(value)
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::ListenV4 => FWPM_LAYER_ALE_AUTH_LISTEN_V4,
        Layer::ListenV6 => FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// The layer setup uses whose key is `key`, if it is one.
fn layer_of(key: &GUID) -> Option<Layer> {
    let key = text(key);
    Layer::ALL
        .into_iter()
        .find(|layer| text(&layer_key(*layer)) == key)
}

/// An open session with the filtering engine, closed when dropped.
struct Engine(HANDLE);

impl Engine {
    #[expect(unsafe_code, reason = "FwpmEngineOpen0 is foreign code")]
    fn open() -> Result<Self> {
        let mut handle = MaybeUninit::<HANDLE>::uninit();
        // SAFETY: no server name (this machine), Windows' own authentication,
        // no identity and no session; `handle` receives the engine's handle.
        let code = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                ptr::null(),
                handle.as_mut_ptr(),
            )
        };
        check(code, "opening the Windows Filtering Platform's engine")?;
        // SAFETY: the call succeeded, so it wrote the handle.
        Ok(Self(unsafe { handle.assume_init() }))
    }
}

impl Drop for Engine {
    #[expect(unsafe_code, reason = "FwpmEngineClose0 is foreign code")]
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// A transaction on `engine`, aborted when dropped before [`Self::commit`].
struct Transaction<'a> {
    engine: &'a Engine,
    open: bool,
}

impl<'a> Transaction<'a> {
    #[expect(unsafe_code, reason = "FwpmTransactionBegin0 is foreign code")]
    fn begin(engine: &'a Engine) -> Result<Self> {
        // SAFETY: an open engine handle; 0 asks for a read-write transaction.
        check(
            unsafe { FwpmTransactionBegin0(engine.0, 0) },
            "starting a filtering transaction",
        )?;
        Ok(Self { engine, open: true })
    }

    #[expect(unsafe_code, reason = "FwpmTransactionCommit0 is foreign code")]
    fn commit(mut self) -> Result<()> {
        self.open = false;
        // SAFETY: the transaction this guard began on its engine.
        check(
            unsafe { FwpmTransactionCommit0(self.engine.0) },
            "committing the filtering transaction",
        )
    }
}

impl Drop for Transaction<'_> {
    #[expect(unsafe_code, reason = "FwpmTransactionAbort0 is foreign code")]
    fn drop(&mut self) {
        if self.open {
            // SAFETY: the transaction this guard began, still open.
            unsafe { FwpmTransactionAbort0(self.engine.0) };
        }
    }
}

/// Memory the engine allocated, freed when dropped.
struct EngineMemory(*mut c_void);

impl Drop for EngineMemory {
    #[expect(unsafe_code, reason = "FwpmFreeMemory0 is foreign code")]
    fn drop(&mut self) {
        // SAFETY: the pointer came from a `Get` call of the engine, freed
        // once; the call sets it to null.
        unsafe { FwpmFreeMemory0(&raw mut self.0) };
    }
}

/// The security descriptor `FWPM_CONDITION_ALE_USER_ID` matches the account
/// `sid` with, freed when the guard drops, and its size.
#[expect(
    unsafe_code,
    reason = "ConvertStringSecurityDescriptorToSecurityDescriptorW is foreign code"
)]
fn account_descriptor(sid: &str) -> Result<(Local, u32)> {
    // The SID goes into a descriptor's text: nothing but its digits.
    let rest = sid.strip_prefix("S-1-5-21-").unwrap_or_default();
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit() || c == '-') {
        bail!("{sid} is not a local account's SID");
    }
    let sddl = wide(&format!("D:(A;;CC;;;{sid})"))?;
    let mut descriptor = MaybeUninit::<PSECURITY_DESCRIPTOR>::uninit();
    let mut size = MaybeUninit::<u32>::uninit();
    // SAFETY: `sddl` is NUL-terminated; on success `descriptor` receives a
    // LocalAlloc'd self-relative descriptor and `size` its length.
    let done = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            descriptor.as_mut_ptr(),
            size.as_mut_ptr(),
        )
    };
    if done == 0 {
        bail!(
            "making the account's filter condition: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: the call succeeded, so it wrote both.
    Ok(unsafe { (Local(descriptor.assume_init()), size.assume_init()) })
}

/// A value of the engine's `FWP_VALUE0` holding `value`.
fn uint16(value: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: value },
    }
}

/// Add `filter` in the transaction open on `engine`: the account's block,
/// or with `ports` the permit to loopback on them.
#[expect(unsafe_code, reason = "FwpmFilterAdd0 is foreign code")]
fn add_filter(
    engine: &Engine,
    filter: &Filter,
    (provider, sublayer): (&mut GUID, GUID),
    user: &mut FWP_BYTE_BLOB,
    ports: [u16; 2],
) -> Result<()> {
    let mut loopback_v6 = FWP_BYTE_ARRAY16 {
        byteArray16: Ipv6Addr::LOCALHOST.octets(),
    };
    let mut range = FWP_RANGE0 {
        valueLow: uint16(ports[0]),
        valueHigh: uint16(ports[1]),
    };
    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_USER_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { sd: user },
        },
    }];
    if filter.permit {
        let address = if filter.layer.v6() {
            FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: &raw mut loopback_v6,
                },
            }
        } else {
            // Host order, as the engine takes an IPv4 address.
            FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: u32::from(Ipv4Addr::LOCALHOST),
                },
            }
        };
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: address,
        });
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: &raw mut range,
                },
            },
        });
    }
    let Ok(count) = u32::try_from(conditions.len()) else {
        bail!("too many filter conditions");
    };
    let (mut name, mut description) = (wide(NAME)?, wide(DESCRIPTION)?);
    let (action, flags, weight) = if filter.permit {
        (
            FWP_ACTION_PERMIT,
            FWPM_FILTER_FLAG_PERSISTENT,
            PERMIT_WEIGHT,
        )
    } else {
        let hard = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        (FWP_ACTION_BLOCK, hard, BLOCK_WEIGHT)
    };
    let value = FWPM_FILTER0 {
        filterKey: guid(&filter.key)?,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags,
        providerKey: provider,
        layerKey: layer_key(filter.layer),
        subLayerKey: sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        },
        numFilterConditions: count,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: action,
            ..FWPM_ACTION0::default()
        },
        ..FWPM_FILTER0::default()
    };
    let mut id = 0u64;
    // SAFETY: an open engine in a transaction; `value` and every buffer its
    // pointers name (names, conditions, the descriptor, the address and the
    // range) live until the call returns, which only reads them; no
    // descriptor of the filter's own.
    let code = unsafe { FwpmFilterAdd0(engine.0, &raw const value, ptr::null_mut(), &raw mut id) };
    check(
        code,
        &format!(
            "adding the network filter {} ({:?})",
            filter.key, filter.layer
        ),
    )
}

/// Install the provider, the sublayer and every filter of [`wfp::plan`] for
/// the account `sid`, with `keys` (provider, sublayer, then one per filter)
/// and the proxy's `ports`, in one transaction: on any failure nothing is
/// kept. The record's part for them.
#[expect(
    unsafe_code,
    reason = "FwpmProviderAdd0 and FwpmSubLayerAdd0 are foreign code"
)]
pub fn install(sid: &str, keys: &[u128], ports: [u16; 2]) -> Result<Wfp> {
    let record = Wfp::new(keys, ports)?;
    let (descriptor, size) = account_descriptor(sid)?;
    let mut user = FWP_BYTE_BLOB {
        size,
        data: descriptor.0.cast(),
    };
    let engine = Engine::open()?;
    let transaction = Transaction::begin(&engine)?;
    let mut provider_key = guid(&record.provider)?;
    let sublayer_key = guid(&record.sublayer)?;
    let (mut name, mut description) = (wide(NAME)?, wide(DESCRIPTION)?);
    let display = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: description.as_mut_ptr(),
    };
    let provider = FWPM_PROVIDER0 {
        providerKey: provider_key,
        displayData: display,
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..FWPM_PROVIDER0::default()
    };
    // SAFETY: an open engine in a transaction; `provider` and its names live
    // until the call returns; no descriptor of its own.
    let code = unsafe { FwpmProviderAdd0(engine.0, &raw const provider, ptr::null_mut()) };
    check(code, "adding OpenMoat's filtering provider")?;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: sublayer_key,
        displayData: display,
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &raw mut provider_key,
        weight: SUBLAYER_WEIGHT,
        ..FWPM_SUBLAYER0::default()
    };
    // SAFETY: as above; `provider_key` outlives the call.
    let code = unsafe { FwpmSubLayerAdd0(engine.0, &raw const sublayer, ptr::null_mut()) };
    check(code, "adding OpenMoat's filtering sublayer")?;
    for filter in &record.filters {
        add_filter(
            &engine,
            filter,
            (&mut provider_key, sublayer_key),
            &mut user,
            ports,
        )?;
    }
    transaction.commit()?;
    drop(descriptor);
    Ok(record)
}

/// Delete the filters, the sublayer and the provider `record` names, in one
/// transaction; one already gone is fine.
#[expect(
    unsafe_code,
    reason = "the engine's DeleteByKey calls are foreign code"
)]
pub fn remove(record: &Wfp) -> Result<()> {
    let engine = Engine::open()?;
    let transaction = Transaction::begin(&engine)?;
    let gone = |code: u32, missing: i32| code == 0 || code == missing.cast_unsigned();
    for filter in &record.filters {
        let key = guid(&filter.key)?;
        // SAFETY: an open engine in a transaction; `key` outlives the call.
        let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &raw const key) };
        if !gone(code, FWP_E_FILTER_NOT_FOUND) {
            check(code, &format!("deleting the network filter {}", filter.key))?;
        }
    }
    let key = guid(&record.sublayer)?;
    // SAFETY: as above.
    let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &raw const key) };
    if !gone(code, FWP_E_SUBLAYER_NOT_FOUND) {
        check(code, "deleting OpenMoat's filtering sublayer")?;
    }
    let key = guid(&record.provider)?;
    // SAFETY: as above.
    let code = unsafe { FwpmProviderDeleteByKey0(engine.0, &raw const key) };
    if !gone(code, FWP_E_PROVIDER_NOT_FOUND) {
        check(code, "deleting OpenMoat's filtering provider")?;
    }
    transaction.commit()
}

/// What the engine holds of `record`: whether its provider and sublayer are
/// there, and each filter's facts; an error when the engine refuses this
/// process (a standard user may not read it).
#[expect(unsafe_code, reason = "the engine's GetByKey calls are foreign code")]
pub fn observe(record: &Wfp) -> Result<Seen> {
    let engine = Engine::open()?;
    let found = |code: u32, missing: i32, what: &str| -> Result<bool> {
        if code == missing.cast_unsigned() {
            return Ok(false);
        }
        check(code, what).map(|()| true)
    };
    let key = guid(&record.provider)?;
    let mut out = MaybeUninit::<*mut FWPM_PROVIDER0>::uninit();
    // SAFETY: an open engine; `key` outlives the call; on success `out`
    // receives memory the engine allocated.
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &raw const key, out.as_mut_ptr()) };
    let provider = found(
        code,
        FWP_E_PROVIDER_NOT_FOUND,
        "reading OpenMoat's provider",
    )?;
    if provider {
        // SAFETY: the call succeeded, so it wrote the pointer.
        drop(EngineMemory(unsafe { out.assume_init() }.cast()));
    }
    let key = guid(&record.sublayer)?;
    let mut out = MaybeUninit::<*mut FWPM_SUBLAYER0>::uninit();
    // SAFETY: as above.
    let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &raw const key, out.as_mut_ptr()) };
    let sublayer = found(
        code,
        FWP_E_SUBLAYER_NOT_FOUND,
        "reading OpenMoat's sublayer",
    )?;
    if sublayer {
        // SAFETY: the call succeeded, so it wrote the pointer.
        drop(EngineMemory(unsafe { out.assume_init() }.cast()));
    }
    let mut filters = Vec::new();
    for filter in &record.filters {
        let key = guid(&filter.key)?;
        let mut out = MaybeUninit::<*mut FWPM_FILTER0>::uninit();
        // SAFETY: as above.
        let code = unsafe { FwpmFilterGetByKey0(engine.0, &raw const key, out.as_mut_ptr()) };
        if !found(code, FWP_E_FILTER_NOT_FOUND, "reading a network filter")? {
            filters.push(None);
            continue;
        }
        // SAFETY: the call succeeded, so it wrote a pointer to a filter the
        // engine allocated, freed when `_free` drops after the last read.
        let pointer = unsafe { out.assume_init() };
        let _free = EngineMemory(pointer.cast());
        // SAFETY: as above; the filter is valid until it is freed.
        let held = unsafe { &*pointer };
        let provider = (!held.providerKey.is_null())
            // SAFETY: a non-null provider key points into the same allocation.
            .then(|| text(unsafe { &*held.providerKey }));
        filters.push(Some(Facts {
            layer: layer_of(&held.layerKey),
            permit: held.action.r#type == FWP_ACTION_PERMIT,
            sublayer: text(&held.subLayerKey),
            provider,
            conditions: held.numFilterConditions,
        }));
    }
    Ok(Seen {
        provider,
        sublayer,
        filters,
    })
}
