//! Linux: the tier would run Firecracker or cloud-hypervisor on KVM, which
//! needs `/dev/kvm` open for reading and writing by the person.

/// The VM monitor this system would use, or why it has none. Opening
/// `/dev/kvm` makes no VM.
pub fn monitor() -> Result<String, String> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => Ok("KVM (`/dev/kvm`), for Firecracker or cloud-hypervisor".to_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
            "no `/dev/kvm`: KVM is off, or this is a VM without nested virtualisation".to_owned(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err("`/dev/kvm` is not open to you: add yourself to its group (often `kvm`)".to_owned())
        }
        Err(e) => Err(format!("`/dev/kvm` cannot be opened: {e}")),
    }
}
