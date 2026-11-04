//! goose's plugin settings that turn OpenMoat's plugin off
//! (`plugins/discovery.rs`, v1.57.0, after the Open Plugins installation
//! settings): `disabledPlugins` and `enabledPlugins` in `settings.json`, read
//! from the project's `.config/goose/settings.local.json`, then its
//! `settings.json`, then the person's; the first file that names a plugin
//! decides it. A plugin named in `disabledPlugins` is not loaded unless an
//! earlier file lists it in `enabledPlugins`; a plugin no file names is
//! loaded, so an `enabledPlugins` list filters nothing out.

use serde_json::{Map, Value};

use crate::contract::{SettingsFile, SettingsReader};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

/// OpenMoat's plugin's name: its directory's.
const PLUGIN: &str = "openmoat";

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        switched_off(file.root)
    }

    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String> {
        switched_off(file.root)
    }
}

/// What in `root` keeps goose from loading OpenMoat's plugin.
pub(super) fn switched_off(root: &Map<String, Value>) -> Vec<String> {
    let mut found = Vec::new();
    let disabled = root.get("disabledPlugins").and_then(Value::as_array);
    if disabled.is_some_and(|list| list.iter().any(|name| name.as_str() == Some(PLUGIN))) {
        found.push("`disabledPlugins` turns OpenMoat's goose plugin off".to_owned());
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn of(value: &Value) -> Vec<String> {
        switched_off(value.as_object().unwrap())
    }

    #[test]
    fn only_disabled_plugins_naming_openmoat_turns_it_off() {
        assert_eq!(of(&json!({ "disabledPlugins": ["openmoat"] })).len(), 1);
        assert_eq!(of(&json!({ "enabledPlugins": ["other"] })), Vec::<String>::new());
        assert_eq!(of(&json!({ "disabledPlugins": ["other"] })), Vec::<String>::new());
        assert_eq!(of(&json!({ "disabledPlugins": "openmoat" })), Vec::<String>::new());
    }
}
