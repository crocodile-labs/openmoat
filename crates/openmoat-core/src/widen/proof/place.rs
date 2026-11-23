//! One matcher's place in a product state of the search (`proof.rs`): its
//! index in the high half, its deterministic state in the low half. A
//! product state is a list of them. A list of integers hashes as one run of
//! bytes (`Hash::hash_slice`), where a list of pairs hashes field by field,
//! and the search looks a state up for every byte class of every state it
//! visits.

/// A matcher's index and state, packed.
pub(super) type Place = u64;

pub(super) fn place(matcher: u32, state: u32) -> Place {
    (u64::from(matcher) << 32) | u64::from(state)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "each half of a place is a u32 (`place`); the casts keep exactly those bits"
)]
pub(super) fn unplace(place: Place) -> (u32, u32) {
    ((place >> 32) as u32, place as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_keeps_both_halves() {
        for (m, s) in [(0, 0), (0, 1), (7, u32::MAX), (u32::MAX, 0), (u32::MAX, u32::MAX)] {
            assert_eq!(unplace(place(m, s)), (m, s));
        }
        assert_ne!(place(1, 0), place(0, 1));
    }
}
