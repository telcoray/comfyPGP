//! Message decryption (Sequoia).

use std::io::Read;

use anyhow::{Result, anyhow, bail};
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, KeyHandle};
use sequoia_openpgp as openpgp;

/// Reads a secret key from a file's contents (armored or binary).
pub fn load_secret_key(bytes: &[u8]) -> Result<Cert> {
    let cert =
        Cert::from_bytes(bytes).map_err(|_| anyhow!("This file does not contain a PGP key."))?;
    if !cert.is_tsk() {
        bail!("This is a public key. To decrypt you need your secret key.");
    }
    Ok(cert)
}

/// Whether any of the key's encryption subkeys is locked with a passphrase.
pub fn needs_passphrase(cert: &Cert) -> bool {
    encryption_keys(cert).any(|key| key.secret().is_encrypted())
}

fn encryption_keys(
    cert: &Cert,
) -> impl Iterator<
    Item = openpgp::packet::Key<
        openpgp::packet::key::SecretParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
> + '_ {
    // No policy filtering on time: old messages must stay readable
    // even after the key has expired or been revoked.
    cert.keys()
        .secret()
        .filter(|ka| ka.key().pk_algo().for_encryption())
        .map(|ka| ka.key().clone().role_into_unspecified())
}

/// Decrypts an OpenPGP message (armored or binary) and returns its contents.
pub fn decrypt(cert: &Cert, passphrase: Option<&str>, message: &[u8]) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let helper = Helper {
        cert,
        passphrase: passphrase.map(Password::from),
        wrong_passphrase: false,
    };

    let mut decryptor = match DecryptorBuilder::from_bytes(message)
        .and_then(|b| b.with_policy(&policy, None, helper))
    {
        Ok(d) => d,
        Err(e) => return Err(explain(e)),
    };

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .map_err(|e| explain(e.into()))?;
    Ok(plaintext)
}

/// Turns Sequoia's errors into messages a newcomer can act on.
fn explain(e: anyhow::Error) -> anyhow::Error {
    let text = format!("{e:#}");
    if text.contains(WRONG_PASSPHRASE) {
        anyhow!("Wrong passphrase.")
    } else if text.contains(NOT_FOR_THIS_KEY) {
        anyhow!("This message was not encrypted for this key.")
    } else if let Some(openpgp::Error::MalformedMessage(_) | openpgp::Error::MalformedPacket(_)) =
        e.downcast_ref::<openpgp::Error>()
    {
        anyhow!("This does not look like a complete PGP message.")
    } else {
        anyhow!("Could not decrypt: {text}")
    }
}

const WRONG_PASSPHRASE: &str = "comfypgp: wrong passphrase";
const NOT_FOR_THIS_KEY: &str = "comfypgp: no matching key";

struct Helper<'a> {
    cert: &'a Cert,
    passphrase: Option<Password>,
    wrong_passphrase: bool,
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    // Signatures are not checked yet: we only decrypt.
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for key in encryption_keys(self.cert) {
            let key = if key.secret().is_encrypted() {
                let Some(pass) = &self.passphrase else {
                    self.wrong_passphrase = true;
                    continue;
                };
                match key.decrypt_secret(pass) {
                    Ok(key) => key,
                    Err(_) => {
                        self.wrong_passphrase = true;
                        continue;
                    }
                }
            } else {
                key
            };

            let mut pair = key.into_keypair()?;
            for pkesk in pkesks {
                if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym_algo)
                    && decrypt(algo, &sk)
                {
                    return Ok(Some(self.cert.clone()));
                }
            }
        }

        if self.wrong_passphrase {
            Err(anyhow!(WRONG_PASSPHRASE))
        } else {
            Err(anyhow!(NOT_FOR_THIS_KEY))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{self, Algorithm, Encoding, KeyRequest, Part};
    use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
    use std::io::Write;

    fn new_key(passphrase: Option<&str>) -> Cert {
        let req = KeyRequest {
            name: "Test".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: passphrase.map(String::from),
        };
        keygen::generate(&req).unwrap().cert
    }

    fn encrypt_to(cert: &Cert, text: &[u8]) -> Vec<u8> {
        let p = StandardPolicy::new();
        let recipients = cert
            .keys()
            .with_policy(&p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption();
        let mut out = Vec::new();
        let message = Message::new(&mut out);
        let message = Armorer::new(message).build().unwrap();
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .unwrap();
        let mut w = LiteralWriter::new(message).build().unwrap();
        w.write_all(text).unwrap();
        w.finalize().unwrap();
        out
    }

    #[test]
    fn decrypts_with_and_without_passphrase() {
        for pass in [None, Some("secret")] {
            let cert = new_key(pass);
            assert_eq!(needs_passphrase(&cert), pass.is_some());
            let msg = encrypt_to(&cert, b"hello comfy");
            assert_eq!(decrypt(&cert, pass, &msg).unwrap(), b"hello comfy");
        }
    }

    #[test]
    fn friendly_errors() {
        let cert = new_key(Some("secret"));
        let msg = encrypt_to(&cert, b"hi");
        let err = decrypt(&cert, Some("nope"), &msg).unwrap_err().to_string();
        assert_eq!(err, "Wrong passphrase.");

        let other = new_key(None);
        let err = decrypt(&other, None, &msg).unwrap_err().to_string();
        assert_eq!(err, "This message was not encrypted for this key.");

        let err = decrypt(&cert, Some("secret"), b"hello")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("Wrong passphrase"), "{err}");
    }

    /// Decrypts a message encrypted by GnuPG, for both key types.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_interop() {
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-dec-{}", std::process::id()));
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
            let public = dir.join("public.asc");
            std::fs::write(
                &public,
                keygen::export(&key, Part::Public, Encoding::Armored).unwrap(),
            )
            .unwrap();

            let gpg = || {
                let mut c = Command::new("gpg");
                c.arg("--homedir").arg(&home).arg("--batch");
                c
            };
            assert!(
                gpg()
                    .arg("--import")
                    .arg(&public)
                    .status()
                    .unwrap()
                    .success()
            );

            let mut child = gpg()
                .args(["--trust-model", "always", "--armor", "--encrypt", "-r"])
                .arg(key.cert.fingerprint().to_hex())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"from gnupg")
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());

            assert_eq!(
                decrypt(&key.cert, Some("secret"), &out.stdout).unwrap(),
                b"from gnupg"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_only_secret_keys() {
        let key = keygen::generate(&KeyRequest {
            name: "Test".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: None,
        })
        .unwrap();
        let secret = keygen::export(&key, Part::Secret, Encoding::Armored).unwrap();
        assert!(load_secret_key(&secret).is_ok());
        let public = keygen::export(&key, Part::Public, Encoding::Armored).unwrap();
        let err = load_secret_key(&public).unwrap_err().to_string();
        assert!(err.contains("public key"), "{err}");
    }
}
