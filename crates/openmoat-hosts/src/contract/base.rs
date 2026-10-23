//! The defaults a host spec takes for the fields it does not name, so a new
//! optional field is added once here rather than in every host's spec.

use super::{Asks, HookLayout, HostDocs, HostSpec, InstallSpec, ProcessSpec, Protect};
use crate::wire::hook_file::nested::Nested;

impl HostSpec {
    /// The value a host spec takes for every field it does not name: `None`
    /// for each optional part. A host spec names its id, display name, asks,
    /// hook-failure text and gaps, and ends with `..HostSpec::BASE`, so a new
    /// optional field is added here once; the registry's tests check that
    /// every host names the required ones.
    pub const BASE: HostSpec = HostSpec {
        id: "",
        display_name: "",
        speaks: None,
        asks: Asks::BASE,
        on_hook_failure: "",
        gaps: "",
        install: None,
        mcp: None,
        sandbox: None,
        project_settings: None,
        detect: None,
        resume_hint: None,
        protect: Protect::BASE,
        process: ProcessSpec::BASE,
        docs: HostDocs::BASE,
    };
}

impl InstallSpec {
    /// The value an install spec takes for every field it does not name: no
    /// relaxed keys and no trust step. An install spec names its directory,
    /// file, hooks and hook format, and ends with `..InstallSpec::BASE`; the
    /// registry's tests check that every host names them.
    pub const BASE: InstallSpec = InstallSpec {
        dir_variable: "",
        dir_name: "",
        config_file: "",
        hooks: &[],
        dir_variable_is_home: false,
        hook_file: HookLayout::Entries(&Nested),
        relaxed_keys: &[],
        trust_step: None,
        location: super::Location::OneDir,
        pinned_form: None,
        extra_files: &[],
    };
}
