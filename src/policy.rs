//! The OpenPGP policy comfyPGP applies to other people's keys.

use openpgp::policy::{HashAlgoSecurity, StandardPolicy};
use openpgp::types::HashAlgorithm;
use sequoia_openpgp as openpgp;

/// Sequoia's standard policy, but accepting SHA-1 in a key's signatures
/// on itself, like GnuPG does. Many keys made before ~2016 use it, and
/// these signatures only need second pre-image resistance, which SHA-1
/// still has. SHA-1 stays rejected wherever collisions matter, such as
/// signatures over messages.
pub fn policy() -> StandardPolicy<'static> {
    let mut p = StandardPolicy::new();
    p.accept_hash_property(
        HashAlgorithm::SHA1,
        HashAlgoSecurity::SecondPreImageResistance,
    );
    p
}
