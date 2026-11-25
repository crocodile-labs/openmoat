use std::io::{Error, ErrorKind};

use super::*;

/// A record's `wfp` part with keys 1, 2, … and the first range.
fn sample() -> Wfp {
    let keys: Vec<u128> = (1..=10).collect();
    Wfp::new(&keys, [47_320, 47_327]).unwrap()
}

/// What the system holds of `wfp` when it matches the record.
fn matching(wfp: &Wfp) -> Seen {
    Seen {
        provider: true,
        sublayer: true,
        filters: wfp
            .filters
            .iter()
            .map(|f| {
                Some(Facts {
                    layer: Some(f.layer),
                    permit: f.permit,
                    sublayer: wfp.sublayer.to_uppercase(),
                    provider: Some(wfp.provider.clone()),
                    conditions: f.conditions(),
                })
            })
            .collect(),
    }
}

/// A block at each of the six layers, a permit at each connect layer only:
/// listens and incoming connections have no permit at all.
#[test]
fn the_plan_blocks_every_layer_and_permits_loopback_connects_only() {
    let plan = plan();
    assert_eq!(plan.len(), 8);
    for layer in Layer::ALL {
        assert!(plan.contains(&(layer, false)), "{layer:?}");
        assert_eq!(plan.contains(&(layer, true)), layer.connect(), "{layer:?}");
    }
    assert_eq!(
        Layer::ALL.iter().filter(|l| l.v6()).count(),
        3,
        "one IPv6 layer per IPv4 one"
    );
}

/// The record's part round-trips through JSON, its keys are GUIDs, and
/// [`Wfp::check`] refuses one no setup writes.
#[test]
fn the_record_part_round_trips_and_a_foreign_one_is_refused() {
    let wfp = sample();
    wfp.check().unwrap();
    let json = serde_json::to_string(&wfp).unwrap();
    assert!(json.contains("\"layer\":\"recv_accept_v6\""), "{json}");
    assert_eq!(serde_json::from_str::<Wfp>(&json).unwrap(), wfp);
    assert_eq!(wfp.provider, "00000000-0000-0000-0000-000000000001");
    assert_eq!(parse_key(&wfp.filters[7].key).unwrap(), 10);

    let mut wide = wfp.clone();
    wide.ports = [47_320, 47_400];
    assert!(wide.check().is_err());
    let mut low = wfp.clone();
    low.ports = [80, 87];
    assert!(low.check().is_err());
    let mut fewer = wfp.clone();
    fewer.filters.pop();
    assert!(fewer.check().is_err());
    let mut opened = wfp.clone();
    opened.filters[2].permit = true;
    assert!(opened.check().is_err(), "a permit at the listen layer");
    let mut bad = wfp;
    bad.provider = "not-a-guid".to_owned();
    assert!(bad.check().is_err());
    assert!(Wfp::new(&[1, 2, 3], [47_320, 47_327]).is_err());
}

/// A random key keeps its randomness but for the version and variant bits.
#[test]
fn a_random_key_is_a_version_4_guid() {
    let key = key(random_key(&"f".repeat(32)).unwrap());
    assert_eq!(key, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    let key = super::key(random_key(&"0".repeat(32)).unwrap());
    assert_eq!(key, "00000000-0000-4000-8000-000000000000");
}

/// The filters as recorded are no drift; one gone, moved, opened or
/// missing its provider is named, as are a gone provider and sublayer.
#[test]
fn drift_names_each_filter_that_differs() {
    let wfp = sample();
    let seen = matching(&wfp);
    assert!(drift(&wfp, &seen).is_empty(), "{:?}", drift(&wfp, &seen));

    let mut gone = seen.clone();
    gone.filters[0] = None;
    gone.provider = false;
    let lines = drift(&wfp, &gone);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("provider"), "{lines:?}");
    assert!(lines[1].contains("block filter") && lines[1].contains("is gone"));

    let edits: [fn(&mut Facts); 5] = [
        |f: &mut Facts| f.permit = !f.permit,
        |f: &mut Facts| f.layer = None,
        |f: &mut Facts| f.conditions = 0,
        |f: &mut Facts| f.provider = None,
        |f: &mut Facts| f.sublayer = "00000000-0000-0000-0000-000000000000".to_owned(),
    ];
    for edit in edits {
        let mut changed = seen.clone();
        edit(changed.filters[1].as_mut().unwrap());
        let lines = drift(&wfp, &changed);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("loopback permit") && lines[0].contains("was changed"));
    }

    let mut short = seen;
    short.filters.truncate(6);
    short.sublayer = false;
    assert_eq!(drift(&wfp, &short).len(), 3);
}

/// Setup takes the first range whose every port is free.
#[test]
fn the_range_is_the_first_whose_ports_are_all_free() {
    assert_eq!(choose_range(|_| true), Some([47_320, 47_327]));
    // One taken port in the first range moves setup to the next.
    assert_eq!(choose_range(|p| p != 47_325), Some([47_328, 47_335]));
    assert_eq!(choose_range(|_| false), None);
    let [first, last] = choose_range(|p| p > 47_700).unwrap();
    assert_eq!(last - first + 1, PORTS);
    assert!(first > 47_700 && last < 49_152, "{first}-{last}");
}

/// A run's proxy takes the first free port of the range and checks it holds
/// that very port; a listener on another one, or no free port, stops it.
#[test]
fn the_proxy_takes_the_first_free_port_it_holds_itself() {
    let ports = [47_320, 47_327];
    let busy = |p: u16| {
        if p < 47_323 {
            Err(Error::from(ErrorKind::AddrInUse))
        } else {
            Ok(p)
        }
    };
    assert_eq!(
        choose_port(ports, busy, |l| Some(*l)).unwrap(),
        (47_323, 47_323)
    );
    assert_eq!(
        choose_port(ports, Ok, |l| Some(*l)).unwrap().1,
        47_320,
        "the first port when all are free"
    );

    // Bound, but to another port than asked: refused, not passed over.
    let error = choose_port(ports, Ok, |_| Some(1)).unwrap_err().to_string();
    assert!(error.contains("holds another address"), "{error}");

    let none = |_: u16| -> std::io::Result<u16> { Err(Error::from(ErrorKind::PermissionDenied)) };
    let error = choose_port(ports, none, |l| Some(*l))
        .unwrap_err()
        .to_string();
    assert!(error.contains("47320-47327"), "{error}");
    assert!(error.contains("agent-account remove"), "{error}");
    assert!(sample().permits(47_327) && !sample().permits(47_328));
}
