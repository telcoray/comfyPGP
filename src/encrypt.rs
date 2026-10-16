//! Message encryption (Sequoia).

use std::io::Write;

use anyhow::{Result, anyhow, bail};
use openpgp::Cert;
use openpgp::crypto::{KeyPair, Password};
use openpgp::packet::Key;
use openpgp::packet::key::{SecretParts, UnspecifiedRole};
use openpgp::parse::Parse;
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer};
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;

use crate::policy::policy;

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

/// The secret key that signs for `cert` today, if there is one.
fn signing_key(cert: &Cert) -> Option<Key<SecretParts, UnspecifiedRole>> {
    let policy = policy();
    let vc = cert.with_policy(&policy, None).ok()?;
    if vc.alive().is_err() {
        return None;
    }
    vc.keys()
        .secret()
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .map(|ka| ka.key().clone().role_into_unspecified())
}

/// Fails with a message saying why this key cannot sign today.
pub fn check_can_sign(cert: &Cert) -> Result<()> {
    if !cert.is_tsk() {
        bail!("Only the public part of this key is saved, so it cannot sign.");
    }
    if signing_key(cert).is_none() {
        bail!("This key cannot sign: it may be expired or revoked.");
    }
    Ok(())
}

/// Whether signing with this key needs its passphrase.
pub fn signing_needs_passphrase(cert: &Cert) -> bool {
    signing_key(cert).is_some_and(|k| k.secret().is_encrypted())
}

/// Unlocks `cert`'s signing key, ready to sign.
pub fn signer(cert: &Cert, passphrase: Option<&str>) -> Result<KeyPair> {
    check_can_sign(cert)?;
    let key = signing_key(cert).expect("checked above");
    let key = if key.secret().is_encrypted() {
        let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) else {
            bail!("Enter the passphrase of your key to sign.");
        };
        match key.clone().decrypt_secret(&Password::from(passphrase)) {
            Ok(key) => key,
            // Sequoia fails to unlock many keys GnuPG protected ("Malformed
            // MPI"): let rPGP unlock them. It also tells a wrong passphrase.
            Err(_) => {
                let unlocked = crate::fallback::unlocked_copy(cert, passphrase)?;
                signing_key(&unlocked)
                    .filter(|k| k.fingerprint() == key.fingerprint())
                    .ok_or_else(|| anyhow!("Could not unlock the signing key."))?
            }
        }
    } else {
        key
    };
    key.into_keypair()
}

/// Encrypts `data` so that any of the `recipients` can open it, signed
/// by `signer` if given.
/// `armor` produces text (`-----BEGIN PGP MESSAGE-----`), otherwise binary.
pub fn encrypt(
    recipients: &[Cert],
    data: &[u8],
    armor: bool,
    signer: Option<KeyPair>,
) -> Result<Vec<u8>> {
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
    let mut message = Encryptor::for_recipients(message, keys).build()?;
    if let Some(signer) = signer {
        message = Signer::new(message, signer)?.build()?;
    }
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
            let msg = encrypt(&[a.clone(), b.clone()], b"for both", armor, None).unwrap();
            assert_eq!(msg.starts_with(b"-----BEGIN PGP MESSAGE-----"), armor);
            for cert in [&a, &b] {
                assert_eq!(
                    decrypt::decrypt(cert, None, &msg, &[]).unwrap().plaintext,
                    b"for both"
                );
            }
        }
    }

    #[test]
    fn uses_only_the_public_part_of_secret_files() {
        let key = new_key();
        let secret = keygen::export(&key, Part::Secret, Encoding::Armored).unwrap();
        let recipient = load_public_key(&secret).unwrap();
        let msg = encrypt(&[recipient], b"hi", true, None).unwrap();
        assert_eq!(
            decrypt::decrypt(&key.cert, None, &msg, &[])
                .unwrap()
                .plaintext,
            b"hi"
        );
    }

    #[test]
    fn rejects_expired_keys_and_garbage() {
        let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 86400);
        let (expired, _) = CertBuilder::general_purpose(Some("Old"))
            .set_creation_time(two_days_ago)
            .set_validity_period(Duration::from_secs(86400))
            .generate()
            .unwrap();
        let err = encrypt(&[expired], b"hi", true, None)
            .unwrap_err()
            .to_string();
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

        let msg = encrypt(&[cert], b"hello old key", true, None).unwrap();
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

    fn locked_key(passphrase: &str) -> Cert {
        keygen::generate(&KeyRequest {
            name: "Signer".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: Some(passphrase.into()),
        })
        .unwrap()
        .cert
    }

    #[test]
    fn signed_messages_verify() {
        let (me, friend) = (locked_key("secret"), new_key().cert);
        assert!(signing_needs_passphrase(&me));
        let signer = signer(&me, Some("secret")).unwrap();
        let msg = encrypt(
            std::slice::from_ref(&friend),
            b"signed by me",
            true,
            Some(signer),
        )
        .unwrap();

        let public_me = me.clone().strip_secret_key_material();
        let d = decrypt::decrypt(&friend, None, &msg, &[public_me]).unwrap();
        assert_eq!(d.plaintext, b"signed by me");
        match d.signature {
            decrypt::SignatureCheck::Good { signer } => {
                assert_eq!(signer.fingerprint(), me.fingerprint())
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn signing_needs_the_right_passphrase_and_a_secret_key() {
        let me = locked_key("secret");
        let err = signer(&me, Some("nope")).map(|_| ()).unwrap_err();
        assert_eq!(err.to_string(), "Wrong passphrase.");
        let err = signer(&me, None).map(|_| ()).unwrap_err();
        assert!(err.to_string().contains("passphrase"), "{err}");
        let public = me.strip_secret_key_material();
        assert!(check_can_sign(&public).is_err());
    }

    /// GnuPG checks the signature on a message comfyPGP signed and encrypted.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_verifies_our_signatures() {
        use openpgp::serialize::SerializeInto;
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The friend has a passphrase: GnuPG 2.5 mis-imports Curve25519 secret
        // keys that have none (see the README).
        let (me, friend) = (locked_key("secret"), locked_key("friend"));
        let import = |cert: Vec<u8>| {
            let path = dir.join("import.pgp");
            std::fs::write(&path, cert).unwrap();
            let out = Command::new("gpg")
                .arg("--homedir")
                .arg(&dir)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--import",
                ])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        import(me.clone().strip_secret_key_material().to_vec().unwrap());
        import(friend.as_tsk().to_vec().unwrap());

        let signer = signer(&me, Some("secret")).unwrap();
        let msg = encrypt(&[friend], b"hello gnupg", true, Some(signer)).unwrap();
        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(&dir)
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "friend",
            ])
            .args(["--status-fd", "2", "--decrypt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&msg).unwrap();
        let out = child.wait_with_output().unwrap();
        let status = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{status}");
        assert_eq!(out.stdout, b"hello gnupg");
        assert!(status.contains("[GNUPG:] GOODSIG"), "{status}");
        assert!(status.contains(&me.fingerprint().to_hex()), "{status}");
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

            let msg = encrypt(
                std::slice::from_ref(&key.cert),
                b"from comfyPGP",
                true,
                None,
            )
            .unwrap();
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
