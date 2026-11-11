use std::os::windows::process::CommandExt as _;
use std::process::Command;

/// `DETACHED_PROCESS`: no console of the hook's.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// `CREATE_NEW_PROCESS_GROUP`: not ended with the hook's group.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// A process group of its own and no console.
pub fn own_group(command: &mut Command) {
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}
