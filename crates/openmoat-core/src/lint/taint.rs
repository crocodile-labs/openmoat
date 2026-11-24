//! Warnings about the policy's `taint:` section (ADR-020): MCP tools the
//! policy adds to the metadata tools, whose results no longer taint a session.

use super::Warning;
use crate::policy::Policy;

/// One warning while `taint.metadata_tools` names a tool: a server that returns
/// page or message text from such a tool brings it in without session taint.
pub(super) fn metadata_tools(policy: &Policy, out: &mut Vec<Warning>) {
    let added = policy
        .taint
        .as_ref()
        .map_or(&[][..], |t| &t.metadata_tools[..]);
    if added.is_empty() {
        return;
    }
    out.push(Warning {
        rule: "taint.metadata_tools".to_owned(),
        message: format!(
            "results of these MCP tools no longer taint the session, so writes to files that \
             run later need no `session-taint` review after them (their output still feeds \
             `injected-input`); list only tools that return the server's own metadata: {}",
            added.join(", ")
        ),
    });
}

/// One warning per `allow` or `defer` group that names a `@data-flow` atom
/// (ADR-126): only deny and review rules decide those atoms, so the pattern
/// does nothing, and whoever wrote it may believe a flow is allowed or
/// reviewed.
pub(super) fn data_flow_outside_review(policy: &Policy, out: &mut Vec<Warning>) {
    let atom = crate::DATA_FLOW_ATOM;
    for group in policy.allow.iter().chain(&policy.defer) {
        if group.shell.iter().any(|p| p.trim_start().starts_with(atom)) {
            out.push(Warning {
                rule: group.id.clone(),
                message: format!(
                    "`{atom}` patterns decide only in `deny` and `review` groups; here they do \
                     nothing. Move them, for example `review: [{{ id: web-data-leaves, shell: \
                     [\"{atom} web publish *\"] }}]` (docs/POLICY.md §4.7)"
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lint::warnings;
    use crate::policy::Policy;

    #[test]
    fn a_data_flow_pattern_in_an_allow_group_is_named() {
        let w = warnings(
            &Policy::parse(
                "version: 1\nallow:\n  - id: flows\n    shell: ['@data-flow web publish *']\n",
            )
            .unwrap(),
        );
        assert!(
            w.iter()
                .any(|w| w.rule == "flows" && w.message.contains("POLICY.md §4.7")),
            "{w:?}"
        );
        let quiet = warnings(
            &Policy::parse(
                "version: 1\nreview:\n  - id: flows\n    shell: ['@data-flow web publish *']\n",
            )
            .unwrap(),
        );
        assert!(!quiet.iter().any(|w| w.rule == "flows"), "{quiet:?}");
    }

    #[test]
    fn added_metadata_tools_are_named_and_the_built_in_list_is_quiet() {
        let warn = |yaml: &str| {
            warnings(&Policy::parse(yaml).unwrap())
                .into_iter()
                .filter(|w| w.rule == "taint.metadata_tools")
                .map(|w| w.message)
                .collect::<Vec<_>>()
        };
        let none: [String; 0] = [];
        assert_eq!(warn("version: 1\ntaint: { metadata_tools: [] }\n"), none);
        assert_eq!(warn(crate::DEFAULT_POLICY), none);
        let w = warn("version: 1\ntaint: { metadata_tools: [mcp__tabs__list_tabs] }\n");
        assert!(
            w.len() == 1 && w[0].contains("mcp__tabs__list_tabs"),
            "{w:?}"
        );
    }
}
