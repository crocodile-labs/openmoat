//! The agent account's network filters (ADR-129 §1 item 4, §2 "Network"):
//! what `openmoat agent-account setup` installs in the Windows Filtering
//! Platform, the record's `wfp` part that names it, how `status` compares
//! the record with what the system holds, and which port a run's proxy
//! takes. Pure, so these tests run on every system; the Win32 calls are in
//! `commands/run/windows/account/filters.rs`.
//!
//! Setup installs, in one WFP transaction, a persistent provider and
//! sublayer of OpenMoat's and, at the connect, listen and receive-accept
//! layers of the ALE (application layer enforcement) for IPv4 and IPv6, a
//! block filter whose `FWPM_CONDITION_ALE_USER_ID` names the account, so
//! every connection and listen of a process of its token is refused. At the
//! two connect layers a permit of higher weight lets it reach `127.0.0.1` or
//! `::1` on a range of [`PORTS`] ports that setup chooses and records, where
//! runs place their proxy. Microsoft's documentation:
//! - ALE layers and `FWPM_CONDITION_ALE_USER_ID` ("a security descriptor …
//!   the access check is done against the token of the application"):
//!   <https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers->,
//!   <https://learn.microsoft.com/windows/win32/fwp/ale-layers>.
//! - Filter arbitration (weights inside a sublayer, block over permit across
//!   sublayers, hard actions):
//!   <https://learn.microsoft.com/windows/win32/fwp/filter-arbitration>.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// How many ports the proxy's range holds.
pub const PORTS: u16 = 8;

/// The first range setup tries: in the registered ports, away from the ones
/// development servers and databases use by habit, and below Windows'
/// dynamic range (49152 and up), whose ports outgoing connections take.
const FIRST_RANGE: u16 = 47_320;

/// How many ranges of [`PORTS`] setup tries, one after the other.
const RANGES: u16 = 64;

/// The ALE layers that hold a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4`: an outgoing connection, a first
    /// UDP send.
    ConnectV4,
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
    ConnectV6,
    /// `FWPM_LAYER_ALE_AUTH_LISTEN_V4`: a TCP listen.
    ListenV4,
    /// `FWPM_LAYER_ALE_AUTH_LISTEN_V6`.
    ListenV6,
    /// `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`: an incoming connection, a first
    /// UDP packet from a new peer.
    RecvAcceptV4,
    /// `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`.
    RecvAcceptV6,
}

impl Layer {
    /// Every layer, in the order setup installs their filters.
    pub const ALL: [Self; 6] = [
        Self::ConnectV4,
        Self::ConnectV6,
        Self::ListenV4,
        Self::ListenV6,
        Self::RecvAcceptV4,
        Self::RecvAcceptV6,
    ];

    /// Whether the layer sees IPv6.
    pub fn v6(self) -> bool {
        matches!(self, Self::ConnectV6 | Self::ListenV6 | Self::RecvAcceptV6)
    }

    /// Whether the layer is a connect layer, the only ones with a permit.
    pub fn connect(self) -> bool {
        matches!(self, Self::ConnectV4 | Self::ConnectV6)
    }
}

/// One filter setup installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Its key, a GUID.
    pub key: String,
    pub layer: Layer,
    /// The loopback permit; otherwise the account's block.
    pub permit: bool,
}

impl Filter {
    /// How many conditions the filter holds: the account alone for a block;
    /// the account, the loopback address and the port range for the permit.
    pub fn conditions(&self) -> u32 {
        if self.permit { 3 } else { 1 }
    }
}

/// The record's `wfp` part: what `remove` deletes and `status` reads back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wfp {
    /// The provider's key.
    pub provider: String,
    /// The sublayer's key.
    pub sublayer: String,
    /// The filters, in [`plan`]'s order.
    pub filters: Vec<Filter>,
    /// The first and last port of the range the runs' proxies listen on.
    pub ports: [u16; 2],
}

/// The filters setup installs, in order: a block at every layer, and a
/// permit at each connect layer.
pub fn plan() -> Vec<(Layer, bool)> {
    Layer::ALL
        .into_iter()
        .flat_map(|layer| {
            let permit = layer.connect().then_some((layer, true));
            std::iter::once((layer, false)).chain(permit)
        })
        .collect()
}

impl Wfp {
    /// The record setup writes for `plan`'s filters with `keys` (provider,
    /// sublayer, then one per filter) and `ports`.
    pub fn new(keys: &[u128], ports: [u16; 2]) -> Result<Self> {
        let planned = plan();
        let [provider, sublayer, filters @ ..] = keys else {
            bail!("the network filters need a key each");
        };
        if filters.len() != planned.len() {
            bail!("the network filters need a key each");
        }
        Ok(Self {
            provider: key(*provider),
            sublayer: key(*sublayer),
            filters: planned
                .into_iter()
                .zip(filters)
                .map(|((layer, permit), k)| Filter {
                    key: key(*k),
                    layer,
                    permit,
                })
                .collect(),
            ports,
        })
    }

    /// Refuse a part no setup writes: a range other than [`PORTS`] ports
    /// above 1023, other filters than [`plan`]'s, a key that is no GUID.
    pub fn check(&self) -> Result<()> {
        let [first, last] = self.ports;
        if first < 1024 || last.checked_sub(first) != Some(PORTS - 1) {
            bail!("the network filters' port range {first}-{last} is not one setup chooses");
        }
        let planned: Vec<(Layer, bool)> =
            self.filters.iter().map(|f| (f.layer, f.permit)).collect();
        if planned != plan() {
            bail!("the network filters' record does not name the filters setup installs");
        }
        let keys = [&self.provider, &self.sublayer]
            .into_iter()
            .chain(self.filters.iter().map(|f| &f.key));
        for k in keys {
            parse_key(k)?;
        }
        Ok(())
    }

    /// Whether `port` is in the recorded range.
    pub fn permits(&self, port: u16) -> bool {
        (self.ports[0]..=self.ports[1]).contains(&port)
    }
}

/// `value` as a GUID's text, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn key(value: u128) -> String {
    let hex = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// A GUID's text as the number [`key`] wrote it from.
pub fn parse_key(text: &str) -> Result<u128> {
    let groups: Vec<&str> = text.split('-').collect();
    let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    if lengths != [8, 4, 4, 4, 12]
        || !groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
    {
        bail!("`{text}` is not a GUID");
    }
    u128::from_str_radix(&groups.concat(), 16).with_context(|| format!("reading the GUID {text}"))
}

/// A random version-4 GUID's number from 16 random bytes as hex (`random_hex`).
pub fn random_key(hex: &str) -> Result<u128> {
    let value = u128::from_str_radix(hex, 16).context("reading random bytes")?;
    // RFC 9562: the version (4) and the variant (`10`) bits.
    Ok((value & !(0xF << 76) & !(0x3 << 62)) | (0x4 << 76) | (0x2 << 62))
}

/// The ranges setup tries for the proxy's ports, in order.
fn ranges() -> impl Iterator<Item = [u16; 2]> {
    (0..RANGES).map(|i| {
        let first = FIRST_RANGE + i * PORTS;
        [first, first + PORTS - 1]
    })
}

/// The first range whose every port `free` finds free when setup runs, so
/// a run later finds one of them free too.
pub fn choose_range(mut free: impl FnMut(u16) -> bool) -> Option<[u16; 2]> {
    ranges().find(|[first, last]| (*first..=*last).all(&mut free))
}

/// The proxy's listener on the first port of `ports` that `bind` takes, and
/// that port, once `bound` says the listener holds that very port: the
/// filters let the agent reach only this range, so a listener elsewhere
/// would be no proxy of its. A port another program holds is passed over;
/// none free is an error that says what to do.
pub fn choose_port<L>(
    ports: [u16; 2],
    mut bind: impl FnMut(u16) -> std::io::Result<L>,
    bound: impl Fn(&L) -> Option<u16>,
) -> Result<(L, u16)> {
    let mut taken = Vec::new();
    for port in ports[0]..=ports[1] {
        match bind(port) {
            Ok(listener) if bound(&listener) == Some(port) => return Ok((listener, port)),
            Ok(_) => bail!("the proxy asked for 127.0.0.1:{port} and holds another address"),
            Err(error) => taken.push(format!("{port}: {error}")),
        }
    }
    bail!(
        "none of the agent account's proxy ports {}-{} is free on 127.0.0.1 ({}); its network \
         filters let the agent reach only these, so the run does not start: stop what holds \
         them, or choose another range with `openmoat agent-account remove` and `setup` from an \
         administrator terminal",
        ports[0],
        ports[1],
        taken.join("; ")
    )
}

/// What the system holds of one recorded filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// Its layer; `None` for a layer setup does not use.
    pub layer: Option<Layer>,
    pub permit: bool,
    /// Its sublayer's key.
    pub sublayer: String,
    /// Its provider's key, if any.
    pub provider: Option<String>,
    pub conditions: u32,
}

/// What the system holds of the record's `wfp` part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    pub provider: bool,
    pub sublayer: bool,
    /// Each recorded filter, in the record's order; `None` when it is gone.
    pub filters: Vec<Option<Facts>>,
}

/// What a process read of the record's network filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Read {
    /// Nothing: the record names none.
    #[default]
    NotAsked,
    /// The engine refused this process (a standard user may not read it).
    Unread,
    /// What it holds of them.
    Seen(Seen),
}

/// How `seen` differs from `wfp`: one line each; empty when it does not.
pub fn drift(wfp: &Wfp, seen: &Seen) -> Vec<String> {
    let mut out = Vec::new();
    if !seen.provider {
        out.push(format!(
            "the network filters' provider {} is gone",
            wfp.provider
        ));
    }
    if !seen.sublayer {
        out.push(format!(
            "the network filters' sublayer {} is gone",
            wfp.sublayer
        ));
    }
    for (index, filter) in wfp.filters.iter().enumerate() {
        let what = format!(
            "the {} filter {} at {:?}",
            if filter.permit {
                "loopback permit"
            } else {
                "block"
            },
            filter.key,
            filter.layer
        );
        match seen.filters.get(index).cloned().flatten() {
            None => out.push(format!("{what} is gone")),
            Some(facts) => {
                let same = facts.layer == Some(filter.layer)
                    && facts.permit == filter.permit
                    && facts.sublayer.eq_ignore_ascii_case(&wfp.sublayer)
                    && facts
                        .provider
                        .is_some_and(|p| p.eq_ignore_ascii_case(&wfp.provider))
                    && facts.conditions == filter.conditions();
                if !same {
                    out.push(format!("{what} was changed"));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
