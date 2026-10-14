//! rPGP fallback for what Sequoia 2 cannot handle with keys and messages
//! made by GnuPG 2.4+ or Kleopatra:
//! - messages in GnuPG's own OCB format (LibrePGP "OCB Encrypted Data"),
//!   which Sequoia 2 no longer reads;
//! - secret keys GnuPG protected with a passphrase, which Sequoia fails
//!   to unlock ("Malformed MPI").
//!
//! rPGP only unlocks the key and removes the encryption layer, handing
//! back the contents and signature packets. Checking the signer's key and
//! the signatures stays with Sequoia and our usual policy.

use std::io::BufReader;

use anyhow::{Result, anyhow};
use openpgp::Cert;
use openpgp::cert::amalgamation::{ValidAmalgamation, ValidateAmalgamation};
use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::{HashAlgoSecurity, Policy};
use openpgp::serialize::SerializeInto;
use openpgp::types::RevocationStatus;
use pgp::composed::{DecryptionOptions, Deserializable, Message, SignedSecretKey, TheRing};
use pgp::ser::Serialize;
use pgp::types::Password;
use sequoia_openpgp as openpgp;

use crate::decrypt::{Decrypted, SignatureCheck, key_problem_reason, pretty_handle};
use crate::policy::policy;

fn to_rpgp(cert: &Cert) -> Result<SignedSecretKey> {
    let tsk = cert.as_tsk().to_vec()?;
    SignedSecretKey::from_bytes(&tsk[..]).map_err(|e| anyhow!("{e}"))
}

/// Whether the passphrase (or none) unlocks one of the key's secret parts,
/// according to rPGP.
pub fn passphrase_unlocks(cert: &Cert, passphrase: Option<&str>) -> bool {
    let Ok(key) = to_rpgp(cert) else {
        return false;
    };
    let password = Password::from(passphrase.unwrap_or(""));
    let opens = |result: pgp::errors::Result<pgp::errors::Result<()>>| matches!(result, Ok(Ok(())));
    key.secret_subkeys
        .iter()
        .any(|sub| opens(sub.key.unlock(&password, |_, _| Ok(()))))
        || opens(key.primary_key.unlock(&password, |_, _| Ok(())))
}

/// Decrypts a message with rPGP. The caller has already checked that the
/// passphrase unlocks `cert`.
pub fn decrypt(
    cert: &Cert,
    passphrase: Option<&str>,
    message: &[u8],
    senders: &[Cert],
) -> Result<Decrypted> {
    let secret_key = to_rpgp(cert)?;
    let password = Password::from(passphrase.unwrap_or(""));

    let msg = if message.trim_ascii_start().starts_with(b"-----BEGIN PGP") {
        Message::from_armor(BufReader::new(message))?.0
    } else {
        Message::from_bytes(message)?
    };
    let ring = TheRing {
        secret_keys: vec![&secret_key],
        key_passwords: vec![&password],
        decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        ..Default::default()
    };
    let (mut msg, _) = msg.decrypt_the_ring(ring, true)?;
    while msg.is_compressed() {
        msg = msg.decompress()?;
    }
    let plaintext = msg.as_data_vec()?;

    let mut signers = senders.to_vec();
    signers.push(cert.clone().strip_secret_key_material());
    let mut signature = SignatureCheck::NotSigned;
    if let Message::Signed { reader, .. } = &msg {
        for i in 0..reader.num_signatures() {
            let Some(sig) = reader.signature(i) else {
                continue;
            };
            // Sequoia parses a signature from the packet body, without header.
            let body = sig.to_bytes()?;
            let check = match Signature::from_bytes(&body) {
                Ok(sig) => check_signature(&sig, &plaintext, &signers),
                Err(_) => SignatureCheck::Bad { signer: None },
            };
            if check.rank() > signature.rank() {
                signature = check;
            }
        }
    }
    Ok(Decrypted {
        plaintext,
        signature,
    })
}

/// Checks a signature over `data` with Sequoia, the way the normal
/// decryption path does: known signer, key valid when it signed, an
/// acceptable hash, and a matching signature.
fn check_signature(sig: &Signature, data: &[u8], certs: &[Cert]) -> SignatureCheck {
    let issuers = sig.get_issuers();
    let found = certs.iter().find_map(|cert| {
        cert.keys()
            .key_handles(issuers.iter())
            .next()
            .map(|ka| (cert, ka))
    });
    let Some((cert, ka)) = found else {
        return SignatureCheck::UnknownSigner {
            issuer: issuers.first().map(pretty_handle),
        };
    };
    let signer = cert.clone();

    let policy = policy();
    let valid = match ka.with_policy(&policy, sig.signature_creation_time()) {
        Ok(valid) => valid,
        Err(e) => {
            return SignatureCheck::KeyProblem {
                signer,
                reason: key_problem_reason(&e),
            };
        }
    };
    let problem = if let RevocationStatus::Revoked(_) = valid.revocation_status() {
        Some("The sender's key has been revoked.")
    } else if valid.alive().is_err() {
        Some("The sender's key had expired when this was signed.")
    } else if !valid.for_signing() {
        Some("The sender's key cannot be used for signatures.")
    } else {
        None
    };
    if let Some(reason) = problem {
        return SignatureCheck::KeyProblem { signer, reason };
    }

    // Signatures over messages need a collision-resistant hash (no SHA-1).
    if policy
        .signature(sig, HashAlgoSecurity::CollisionResistance)
        .is_err()
    {
        return SignatureCheck::Bad {
            signer: Some(signer),
        };
    }
    match sig.clone().verify_message(valid.key(), data) {
        Ok(()) => SignatureCheck::Good { signer },
        Err(_) => SignatureCheck::Bad {
            signer: Some(signer),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::decrypt::{self, SignatureCheck};
    use crate::keygen::{self, Algorithm, KeyRequest};
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::serialize::SerializeInto;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    /// A throwaway GnuPG home with a key made by GnuPG itself, so that
    /// GnuPG encrypts to it in its own OCB format.
    struct Gpg {
        home: PathBuf,
    }

    impl Gpg {
        fn new(name: &str) -> Self {
            let home =
                std::env::temp_dir().join(format!("comfypgp-ocb-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&home).unwrap();
            Gpg { home }
        }

        fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
            let mut child = Command::new("gpg")
                .arg("--homedir")
                .arg(&self.home)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--trust-model",
                    "always",
                ])
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(stdin).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            out
        }

        /// Makes a GnuPG key and returns it as comfyPGP would load it.
        fn new_key(&self, passphrase: &str) -> Cert {
            self.run(
                &[
                    "--passphrase",
                    passphrase,
                    "--quick-gen-key",
                    "GnuPG Key",
                    "default",
                    "default",
                    "never",
                ],
                b"",
            );
            let secret = self.run(
                &[
                    "--passphrase",
                    passphrase,
                    "--armor",
                    "--export-secret-keys",
                    "GnuPG Key",
                ],
                b"",
            );
            decrypt::load_secret_key(&secret.stdout).unwrap()
        }

        fn import(&self, cert: &Cert) {
            let path: &Path = &self.home.join("import.pgp");
            std::fs::write(path, cert.as_tsk().to_vec().unwrap()).unwrap();
            self.run(&["--import", path.to_str().unwrap()], b"");
        }

        fn encrypt(&self, extra: &[&str], text: &[u8]) -> Vec<u8> {
            let mut args = vec!["--armor", "--force-ocb", "--encrypt", "-r", "GnuPG Key"];
            args.extend_from_slice(extra);
            let out = self.run(&args, text).stdout;
            assert!(String::from_utf8_lossy(&out).contains("BEGIN PGP MESSAGE"));
            out
        }
    }

    impl Drop for Gpg {
        fn drop(&mut self) {
            let _ = Command::new("gpgconf")
                .arg("--homedir")
                .arg(&self.home)
                .args(["--kill", "gpg-agent"])
                .output();
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn comfy_key() -> Cert {
        keygen::generate(&KeyRequest {
            name: "Comfy Sender".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: None,
        })
        .unwrap()
        .cert
    }

    #[test]
    #[ignore]
    fn plain_ocb_message() {
        let gpg = Gpg::new("plain");
        let me = gpg.new_key("");
        let msg = gpg.encrypt(&[], b"ocb from gnupg");
        let d = decrypt::decrypt(&me, None, &msg, &[]).unwrap();
        assert_eq!(d.plaintext, b"ocb from gnupg");
        assert!(matches!(d.signature, SignatureCheck::NotSigned));
    }

    #[test]
    #[ignore]
    fn ocb_with_passphrase() {
        let gpg = Gpg::new("pass");
        let me = gpg.new_key("secret");
        assert!(decrypt::needs_passphrase(&me));
        let msg = gpg.encrypt(&[], b"locked");
        let err = decrypt::decrypt(&me, Some("nope"), &msg, &[]).unwrap_err();
        assert_eq!(err.to_string(), "Wrong passphrase.");
        let d = decrypt::decrypt(&me, Some("secret"), &msg, &[]).unwrap();
        assert_eq!(d.plaintext, b"locked");
    }

    /// Sequoia cannot unlock secret keys GnuPG protected with a passphrase,
    /// even for messages in the classic format.
    #[test]
    #[ignore]
    fn classic_message_to_protected_gnupg_key() {
        let gpg = Gpg::new("classic");
        let me = gpg.new_key("secret");
        let public = me.clone().strip_secret_key_material();
        let msg = crate::encrypt::encrypt(&[public], b"classic", true).unwrap();
        let err = decrypt::decrypt(&me, Some("nope"), &msg, &[]).unwrap_err();
        assert_eq!(err.to_string(), "Wrong passphrase.");
        let d = decrypt::decrypt(&me, Some("secret"), &msg, &[]).unwrap();
        assert_eq!(d.plaintext, b"classic");
    }

    #[test]
    #[ignore]
    fn signed_ocb_message() {
        let gpg = Gpg::new("signed");
        let me = gpg.new_key("");
        let sender = comfy_key();
        gpg.import(&sender);
        let fpr = sender.fingerprint().to_hex();
        let msg = gpg.encrypt(&["--sign", "--local-user", &fpr], b"signed ocb");

        let public = sender.clone().strip_secret_key_material();
        let d = decrypt::decrypt(&me, None, &msg, &[public]).unwrap();
        assert_eq!(d.plaintext, b"signed ocb");
        match d.signature {
            SignatureCheck::Good { signer } => {
                assert_eq!(signer.fingerprint(), sender.fingerprint())
            }
            other => panic!("{other:?}"),
        }

        let d = decrypt::decrypt(&me, None, &msg, &[]).unwrap();
        assert!(
            matches!(
                d.signature,
                SignatureCheck::UnknownSigner { issuer: Some(_) }
            ),
            "{:?}",
            d.signature
        );

        // A different key with the same name must not pass as the sender.
        let impostor = comfy_key().strip_secret_key_material();
        let d = decrypt::decrypt(&me, None, &msg, &[impostor]).unwrap();
        assert!(
            matches!(d.signature, SignatureCheck::UnknownSigner { .. }),
            "{:?}",
            d.signature
        );
    }

    #[test]
    #[ignore]
    fn tampered_ocb_message_fails() {
        let gpg = Gpg::new("tamper");
        let me = gpg.new_key("");
        let armored = gpg.encrypt(&[], &[b'x'; 200]);

        // Flip one bit inside the encrypted data, then re-armor.
        let mut binary = sequoia_openpgp::armor::Reader::from_bytes(
            &armored,
            sequoia_openpgp::armor::ReaderMode::Tolerant(None),
        );
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut binary, &mut bytes).unwrap();
        let at = bytes.len() - 40;
        bytes[at] ^= 0x01;

        assert!(decrypt::decrypt(&me, None, &bytes, &[]).is_err());
    }
}
