//! pi's published security advisories that name a fixed version
//! (earendil-works/pi security advisories, read 2026-10-25), newest fix
//! first. The releases of the old package `@mariozechner/pi-coding-agent`
//! (up to 0.73.1) got no fix; the fix is a release of
//! `@earendil-works/pi-coding-agent` from the version named, so the ranges run
//! across both.

use crate::contract::{Advisories, Advisory, Platform};

pub(super) const ADVISORIES: Advisories = Advisories {
    program: "pi",
    list: &[
        Advisory::new(
            "GHSA-mqxh-6gq7-558m",
            "a project's own extensions loaded without approval",
            ((0, 0, 0), (0, 79, 0)),
            &[],
            "https://github.com/advisories/GHSA-mqxh-6gq7-558m",
        ),
        Advisory::new(
            "GHSA-r95r-rj6r-c39x",
            "a race in writing auth.json can expose stored credentials",
            ((0, 28, 0), (0, 78, 1)),
            &[],
            "https://github.com/advisories/GHSA-r95r-rj6r-c39x",
        ),
        Advisory::new(
            "GHSA-jfgx-wxx8-mp94",
            "predictable temporary extension paths let another user on the machine run code",
            ((0, 50, 0), (0, 78, 1)),
            &[Platform::Linux, Platform::Wsl],
            "https://github.com/advisories/GHSA-jfgx-wxx8-mp94",
        ),
        Advisory::new(
            "GHSA-7v5m-pr3q-6453",
            "script injection in HTML session exports",
            ((0, 27, 5), (0, 78, 1)),
            &[],
            "https://github.com/advisories/GHSA-7v5m-pr3q-6453",
        ),
    ],
};
