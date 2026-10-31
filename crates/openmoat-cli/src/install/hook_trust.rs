//! Advisory host-owned trust inspection for status and doctor only.

use super::HostConfig;

pub(super) fn warning(config: &HostConfig) -> Option<String> {
    let reader = config.host.spec().install.as_ref()?.hook_trust?;
    let document = std::fs::read_to_string(config.dir().join(reader.toml_file()))
        .ok()
        .and_then(|text| text.parse::<toml_edit::DocumentMut>().ok())
        .map_or(serde_json::Value::Null, |doc| {
            crate::mcp::servers::toml_to_json(doc.as_item())
        });
    reader.warning(
        &config.read().ok()?,
        &document,
        &config.settings_path.display().to_string(),
        crate::integrity::sha256_hex,
    )
}
