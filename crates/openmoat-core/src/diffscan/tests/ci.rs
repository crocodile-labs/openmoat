//! GitHub workflows.

use super::{File, found, quiet};
use crate::diffscan::{
    CI_INJECTION, CI_PERMISSIONS, CI_PR_TARGET, CI_SECRET_OUT, CI_UNPINNED, Level,
};

const WORKFLOW: &str = ".github/workflows/ci.yml";
const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

#[test]
fn pull_request_target_with_a_head_checkout_is_denied() {
    let file = File::new(
        WORKFLOW,
        &[
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  build:",
            "    steps:",
            &format!("      - uses: actions/checkout@{SHA} # v7"),
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}",
            "      - run: npm ci && npm test",
        ],
    );
    assert_eq!(found(&file), [(CI_PR_TARGET, Level::Deny)]);
    let gh = File::new(
        WORKFLOW,
        &[
            "on: [pull_request_target]",
            "      - run: gh pr checkout ${{ github.event.number }}",
        ],
    );
    assert!(
        found(&gh).contains(&(CI_PR_TARGET, Level::Deny)),
        "{:?}",
        found(&gh)
    );
    // the trigger alone: review
    let trigger_only = File::new(
        WORKFLOW,
        &["on:", "  pull_request_target:", "    types: [opened]"],
    );
    assert_eq!(found(&trigger_only), [(CI_PR_TARGET, Level::Review)]);
    // a head checkout under `pull_request` has no secrets to lose
    quiet(&File::new(
        WORKFLOW,
        &[
            "on: pull_request",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}",
        ],
    ));
}

#[test]
fn write_permissions_are_reported_once() {
    assert_eq!(
        found(&File::new(WORKFLOW, &["permissions: write-all"])),
        [(CI_PERMISSIONS, Level::Review)]
    );
    let file = File::new(
        WORKFLOW,
        &[
            "permissions:",
            "  contents: write",
            "  packages: write",
            "  id-token: write",
        ],
    );
    let hits = file.hits();
    assert_eq!(found(&file), [(CI_PERMISSIONS, Level::Review)]);
    assert!(
        hits[0].reason.contains("contents, packages, id-token"),
        "{hits:?}"
    );
    quiet(&File::new(
        WORKFLOW,
        &["permissions:", "  contents: read", "  pull-requests: read"],
    ));
}

#[test]
fn an_action_not_pinned_to_a_full_sha_needs_review() {
    for uses in [
        "      - uses: actions/checkout@v4",
        "      - uses: someone/action@main",
        "      - uses: someone/action",
        "      - uses: \"someone/action/sub@v1.2.3\"",
        "      - uses: docker://alpine:3.20",
        &format!("      - uses: actions/checkout@{}", &SHA[..12]),
    ] {
        assert_eq!(
            found(&File::new(WORKFLOW, &[uses])),
            [(CI_UNPINNED, Level::Review)],
            "{uses}"
        );
    }
    // pinning an action is quiet
    quiet(&File::edit(
        WORKFLOW,
        &["      - uses: actions/checkout@v4"],
        &[&format!("      - uses: actions/checkout@{SHA} # v4.2.2")],
    ));
    quiet(&File::new(
        WORKFLOW,
        &[
            "      - uses: ./.github/actions/setup",
            "      - uses: docker://alpine@sha256:0123abcd",
        ],
    ));
    // the same in a composite action
    assert_eq!(
        found(&File::new("action.yml", &["    - uses: actions/cache@v4"])),
        [(CI_UNPINNED, Level::Review)]
    );
}

#[test]
fn an_event_field_inside_a_script_is_injection() {
    for (lines, level) in [
        (
            vec!["      - run: echo \"${{ github.event.issue.title }}\""],
            Level::Deny,
        ),
        (
            vec![
                "      - run: |",
                "          git checkout ${{ github.head_ref }}",
            ],
            Level::Deny,
        ),
        (
            vec!["          echo ${{ github.event.pull_request.body }} > notes"],
            Level::Deny,
        ),
        (
            vec![
                "        with:",
                "          script: |",
                "            console.log('${{ github.event.comment.body }}')",
            ],
            Level::Deny,
        ),
        (
            vec!["      - run: ./deploy ${{ inputs.target }}"],
            Level::Review,
        ),
        (
            vec!["      - run: echo ${{ github.event.pull_request.number }}"],
            Level::Review,
        ),
    ] {
        let file = File::new(WORKFLOW, &lines);
        assert_eq!(found(&file), [(CI_INJECTION, level)], "{lines:?}");
    }
}

#[test]
fn an_event_field_passed_as_data_is_quiet() {
    quiet(&File::new(
        WORKFLOW,
        &[
            "      - name: greet",
            "        if: ${{ github.event.pull_request.head.repo.fork }}",
            "        env:",
            "          TITLE: ${{ github.event.issue.title }}",
            "        run: echo \"$TITLE\"",
            "      - uses: peter-evans/create-pull-request@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "        with:",
            "          body: |",
            "            Closes ${{ github.event.issue.title }}",
            "          title: ${{ github.event.issue.title }}",
            "      - run: echo \"${{ github.sha }} ${{ github.event_name }} ${{ matrix.os }}\"",
            "      # run: echo ${{ github.event.issue.title }}",
        ],
    ));
}

#[test]
fn a_secret_printed_or_sent_is_reported() {
    assert_eq!(
        found(&File::new(
            WORKFLOW,
            &["      - run: echo ${{ secrets.NPM_TOKEN }}"]
        )),
        [(CI_SECRET_OUT, Level::Deny)]
    );
    assert_eq!(
        found(&File::new(
            WORKFLOW,
            &["          echo '${{ toJSON(secrets) }}' > all.json"]
        )),
        [(CI_SECRET_OUT, Level::Deny)]
    );
    assert_eq!(
        found(&File::new(
            WORKFLOW,
            &[
                "      - run: curl -H \"Authorization: Bearer ${{ secrets.DEPLOY }}\" https://deploy.acme.dev/hook"
            ]
        )),
        [(CI_SECRET_OUT, Level::Review)]
    );
    quiet(&File::new(
        WORKFLOW,
        &[
            "        env:",
            "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}",
            "      - run: echo \"${{ secrets.KEY }}\" > key.pem",
            "      - run: echo \"${{ secrets.PASS }}\" | docker login -u me --password-stdin",
            "      - run: npm publish --provenance",
        ],
    ));
}

#[test]
fn other_yaml_is_not_a_workflow() {
    quiet(&File::new(
        "config/app.yml",
        &[
            "uses: someone/thing@main",
            "run: echo ${{ github.event.issue.title }}",
        ],
    ));
}
