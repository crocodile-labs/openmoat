//! A project's Cursor `hooks.json`: its hooks run beside OpenMoat's. Cursor
//! has no user setting that turns OpenMoat's hook off.

use crate::contract::{SettingsFile, SettingsReader, set};

#[derive(Debug)]
pub(crate) struct Reader;

pub(crate) static READER: Reader = Reader;

impl SettingsReader for Reader {
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String> {
        if set(file.root.get("hooks")) {
            vec!["`hooks` adds hooks that run commands".to_owned()]
        } else {
            Vec::new()
        }
    }

    fn switched_off(&self, _file: &SettingsFile<'_>) -> Vec<String> {
        Vec::new()
    }
}
