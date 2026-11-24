//! Windows and other systems: the tier's design covers macOS and Linux only
//! (Hyper-V is not part of it).

/// Why this system has no VM monitor the tier would use.
pub fn monitor() -> Result<String, String> {
    Err(
        "the microVM tier is designed for macOS and Linux; Windows (Hyper-V) and other \
         systems are not covered"
            .to_owned(),
    )
}
