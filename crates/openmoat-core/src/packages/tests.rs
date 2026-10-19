use super::{Ecosystem, TOP, list_len, near_miss, one_edit};

use Ecosystem::{Crates, Go, Npm, Pypi, Rubygems};

#[test]
fn typos_of_popular_names_are_near_misses() {
    for (ecosystem, name, meant) in [
        (Pypi, "reqeusts", "requests"),
        (Pypi, "requets", "requests"),
        (Pypi, "nunpy", "numpy"),
        (Pypi, "pandsa", "pandas"),
        (Pypi, "beautifulsoup5", "beautifulsoup4"),
        (Npm, "lodahs", "lodash"),
        (Npm, "expresss", "express"),
        (Npm, "axois", "axios"),
        (Npm, "@types/nodee", "@types/node"),
        (Crates, "tokoi", "tokio"),
        (Crates, "serde-jsonn", "serde_json"),
        (Rubygems, "nokogri", "nokogiri"),
        (Go, "github.com/spf13/cobar", "github.com/spf13/cobra"),
    ] {
        assert_eq!(near_miss(ecosystem, name), Some(meant), "{name}");
    }
}

#[test]
fn separator_doubling_and_affix_tricks_are_near_misses() {
    for (ecosystem, name, meant) in [
        (Npm, "react_dom", "react-dom"),
        (Npm, "reactdom", "react-dom"),
        (Npm, "lodash.js", "lodash"),
        (Npm, "node-axios", "axios"),
        (Npm, "express-js", "express"),
        (Npm, "commmmander", "commander"),
        (Pypi, "pythondateutil", "python-dateutil"),
        (Pypi, "python-requests", "requests"),
        (Pypi, "requests-python", "requests"),
        (Pypi, "dateutil", "python-dateutil"),
        (Pypi, "pytorch", "torch"),
        (Crates, "rust-serde", "serde"),
        (Crates, "tokio-rs", "tokio"),
        (Rubygems, "ruby-rails", "rails"),
        (Rubygems, "factory-bot", "factory_bot"),
    ] {
        assert_eq!(near_miss(ecosystem, name), Some(meant), "{name}");
    }
}

#[test]
fn popular_and_unrelated_names_are_not_near_misses() {
    for (ecosystem, name) in [
        (Pypi, "requests"),
        (Pypi, "numpy"),
        (Pypi, "pandas"),
        (Pypi, "Django"),
        (Pypi, "python_dateutil"),
        (Pypi, "PyYAML"),
        (Pypi, "pyaml"),
        (Pypi, "some-company-internal-tool"),
        (Npm, "react"),
        (Npm, "react-dom"),
        (Npm, "preact"),
        (Npm, "mysql2"),
        (Npm, "left-pad-pro"),
        (Npm, "some-new-internal-pkg"),
        (Npm, "@acme/widgets"),
        (Crates, "serde"),
        (Crates, "serde-json"),
        (Crates, "md5"),
        (Crates, "my-brand-new-crate"),
        (Rubygems, "rails"),
        (Rubygems, "factory_bot"),
        (Go, "github.com/spf13/cobra"),
        (Go, "github.com/labstack/echo/v5"),
        (Go, "github.com/acme/internal-service"),
    ] {
        assert_eq!(near_miss(ecosystem, name), None, "{name}");
    }
}

#[test]
fn short_names_are_never_near_misses() {
    // `vue`/`vua`, `jest`/`jist`: among names this short, one letter separates
    // two real packages
    for (ecosystem, name) in [(Npm, "vua"), (Npm, "jist"), (Pypi, "sixx"), (Crates, "syb")] {
        assert_eq!(near_miss(ecosystem, name), None, "{name}");
    }
}

#[test]
fn one_edit_is_optimal_string_alignment_distance_one() {
    for (a, b) in [
        ("requests", "reqeusts"),
        ("requests", "requets"),
        ("requests", "requestss"),
        ("requests", "rrequests"),
        ("requests", "requestz"),
        ("lodash", "lodahs"),
    ] {
        assert!(one_edit(a, b) && one_edit(b, a), "{a} {b}");
    }
    for (a, b) in [
        ("requests", "requests"),
        ("requests", "reqeustss"),
        ("lodash", "ldoahs"),
        ("abc", "abcde"),
    ] {
        assert!(!one_edit(a, b), "{a} {b}");
    }
}

#[test]
fn every_list_is_loaded_and_sized_as_documented() {
    for (ecosystem, at_least) in [
        (Npm, 500),
        (Pypi, 500),
        (Crates, 300),
        (Rubygems, 200),
        (Go, 120),
    ] {
        let n = list_len(ecosystem);
        assert!((at_least..=2000).contains(&n), "{}: {n}", ecosystem.id());
        // each name once, as the registry compares names
        let top = &TOP[ecosystem.index()];
        assert_eq!(top.known.len(), n, "{} has a duplicate", ecosystem.id());
    }
}

#[test]
fn registries_compare_names_their_own_way() {
    assert_eq!(Pypi.normalise("Python_Dateutil"), "python-dateutil");
    assert_eq!(Pypi.normalise("zope.interface"), "zope-interface");
    assert_eq!(Pypi.normalise("a-_.b"), "a-b");
    assert_eq!(Crates.normalise("Serde_JSON"), "serde-json");
    assert_eq!(Npm.normalise("lodash_es"), "lodash_es");
    assert_eq!(
        Go.normalise("github.com/labstack/echo/v4"),
        "github.com/labstack/echo"
    );
    assert_eq!(
        Go.normalise("github.com/vishvananda/netlink"),
        "github.com/vishvananda/netlink"
    );
}
