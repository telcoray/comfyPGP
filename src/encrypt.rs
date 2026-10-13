//! Message encryption (Sequoia).

use std::io::Write;

use anyhow::{Result, anyhow, bail};
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Recipient};
use openpgp::types::{HashAlgorithm, RevocationStatus};
use sequoia_openpgp as openpgp;

/// Sequoia's standard policy, but accepting SHA-1 in a key's signatures
/// on itself, like GnuPG does. Many keys made before ~2016 use it, and
/// these signatures only need second pre-image resistance, which SHA-1
/// still has. SHA-1 stays rejected wherever collisions matter.
fn policy() -> StandardPolicy<'static> {
    let mut p = StandardPolicy::new();
    p.accept_hash_property(
        HashAlgorithm::SHA1,
        HashAlgoSecurity::SecondPreImageResistance,
    );
    p
}

/// Reads a recipient's key (armored or binary). A secret key file works
/// too: only its public part is used.
pub fn load_public_key(bytes: &[u8]) -> Result<Cert> {
    let cert = Cert::from_bytes(bytes).map_err(|_| anyhow!("This does not contain a PGP key."))?;
    check_can_encrypt(&cert)?;
    Ok(cert)
}

/// Fails with a message saying why nobody could encrypt to this key today.
pub fn check_can_encrypt(cert: &Cert) -> Result<()> {
    if has_encryption_key(cert, &policy()) {
        return Ok(());
    }
    let p = policy();
    let Ok(vc) = cert.with_policy(&p, None) else {
        bail!("This key is damaged or uses technology comfyPGP does not support.");
    };
    if let RevocationStatus::Revoked(_) = vc.revocation_status() {
        bail!("This key has been revoked by its owner.");
    }
    if vc.alive().is_err() {
        bail!("This key has expired. Ask its owner for an updated copy.");
    }
    bail!("This key cannot be used to encrypt.")
}

/// Whether the key only works thanks to the SHA-1 exception in [`policy`],
/// so the UI can suggest asking for a newer key.
pub fn uses_old_technology(cert: &Cert) -> bool {
    has_encryption_key(cert, &policy()) && !has_encryption_key(cert, &StandardPolicy::new())
}

fn has_encryption_key(cert: &Cert, policy: &dyn Policy) -> bool {
    cert.with_policy(policy, None).is_ok_and(|vc| {
        vc.alive().is_ok()
            && vc
                .keys()
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .next()
                .is_some()
    })
}

/// Encrypts `data` so that any of the `recipients` can open it.
/// `armor` produces text (`-----BEGIN PGP MESSAGE-----`), otherwise binary.
pub fn encrypt(recipients: &[Cert], data: &[u8], armor: bool) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("Add at least one recipient.");
    }
    let policy = policy();
    let mut keys: Vec<Recipient> = Vec::new();
    for cert in recipients {
        check_can_encrypt(cert)?;
        let vc = cert.with_policy(&policy, None)?;
        keys.extend(
            vc.keys()
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .map(Recipient::from),
        );
    }

    let mut out = Vec::new();
    let mut message = Message::new(&mut out);
    if armor {
        message = Armorer::new(message).build()?;
    }
    let message = Encryptor::for_recipients(message, keys).build()?;
    let mut writer = LiteralWriter::new(message).build()?;
    writer.write_all(data)?;
    writer.finalize()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt;
    use crate::keygen::{self, Algorithm, Encoding, KeyRequest, Part};
    use openpgp::cert::CertBuilder;
    use std::time::{Duration, SystemTime};

    fn new_key() -> keygen::GeneratedKey {
        keygen::generate(&KeyRequest {
            name: "Test".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: None,
        })
        .unwrap()
    }

    #[test]
    fn every_recipient_can_decrypt() {
        let (a, b) = (new_key().cert, new_key().cert);
        for armor in [true, false] {
            let msg = encrypt(&[a.clone(), b.clone()], b"for both", armor).unwrap();
            assert_eq!(msg.starts_with(b"-----BEGIN PGP MESSAGE-----"), armor);
            for cert in [&a, &b] {
                assert_eq!(decrypt::decrypt(cert, None, &msg).unwrap(), b"for both");
            }
        }
    }

    #[test]
    fn uses_only_the_public_part_of_secret_files() {
        let key = new_key();
        let secret = keygen::export(&key, Part::Secret, Encoding::Armored).unwrap();
        let recipient = load_public_key(&secret).unwrap();
        let msg = encrypt(&[recipient], b"hi", true).unwrap();
        assert_eq!(decrypt::decrypt(&key.cert, None, &msg).unwrap(), b"hi");
    }

    #[test]
    fn rejects_expired_keys_and_garbage() {
        let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 86400);
        let (expired, _) = CertBuilder::general_purpose(Some("Old"))
            .set_creation_time(two_days_ago)
            .set_validity_period(Duration::from_secs(86400))
            .generate()
            .unwrap();
        let err = encrypt(&[expired], b"hi", true).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");

        let err = load_public_key(b"not a key").unwrap_err().to_string();
        assert_eq!(err, "This does not contain a PGP key.");
    }

    /// Old keys whose self-signatures use SHA-1 (common before ~2016) are
    /// accepted, flagged as old, and GnuPG can read what we encrypt to them.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn old_sha1_keys() {
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-sha1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gpg = |args: &[&str]| {
            let out = Command::new("gpg")
                .arg("--homedir")
                .arg(&dir)
                .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
                .args(["--cert-digest-algo", "SHA1"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        };
        gpg(&["--quick-gen-key", "Old Key", "rsa2048", "sign", "never"]);
        let listing = String::from_utf8(gpg(&["--with-colons", "--list-keys", "Old Key"])).unwrap();
        let fpr = listing
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap()
            .to_string();
        gpg(&["--quick-add-key", &fpr, "rsa2048", "encr", "never"]);

        let cert = load_public_key(&gpg(&["--armor", "--export", &fpr])).unwrap();
        assert!(uses_old_technology(&cert));
        assert!(!uses_old_technology(&new_key().cert));

        let msg = encrypt(&[cert], b"hello old key", true).unwrap();
        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(&dir)
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--decrypt",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&msg).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"hello old key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GnuPG decrypts what comfyPGP encrypts, for both key types.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_interop() {
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-enc-{}", std::process::id()));
        let home = dir.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();

        for algorithm in [Algorithm::Cv25519, Algorithm::Rsa4096] {
            let key = keygen::generate(&KeyRequest {
                name: "Test".into(),
                email: String::new(),
                algorithm,
                validity: None,
                passphrase: Some("secret".into()),
            })
            .unwrap();
            let secret = dir.join("secret.asc");
            std::fs::write(
                &secret,
                keygen::export(&key, Part::Secret, Encoding::Armored).unwrap(),
            )
            .unwrap();

            let gpg = || {
                let mut c = Command::new("gpg");
                c.arg("--homedir").arg(&home).args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "secret",
                ]);
                c
            };
            assert!(
                gpg()
                    .arg("--import")
                    .arg(&secret)
                    .status()
                    .unwrap()
                    .success()
            );

            let msg = encrypt(&[key.cert.clone()], b"from comfyPGP", true).unwrap();
            let mut child = gpg()
                .arg("--decrypt")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&msg).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stdout, b"from comfyPGP");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
