use super::{Netns, refuse_port_only};

#[test]
fn require_refuses_a_port_only_network() {
    let why = "moat run: the network is restricted by port only";
    let refused = refuse_port_only(Netns::Require, None, Some(why)).unwrap_err();
    assert!(format!("{refused:#}").contains("--netns=require"));
    assert!(format!("{refused:#}").contains(why));
    assert!(refuse_port_only(Netns::Require, None, None).is_ok());
    assert!(
        refuse_port_only(Netns::Auto, None, Some(why)).is_ok(),
        "the default"
    );
    assert!(refuse_port_only(Netns::Auto, None, None).is_ok());
}

#[test]
fn a_policy_that_requires_the_boundary_refuses_whatever_the_flag_says() {
    let why = "moat run: the network is restricted by port only";
    for netns in [Netns::Auto, Netns::Require] {
        let refused = refuse_port_only(netns, Some("your policy"), Some(why)).unwrap_err();
        let shown = format!("{refused:#}");
        assert!(shown.contains("your policy"), "{shown}");
        assert!(shown.contains("require.run: full-boundary"), "{shown}");
        assert!(shown.contains(why), "{shown}");
        assert!(refuse_port_only(netns, Some("your policy"), None).is_ok());
    }
}
