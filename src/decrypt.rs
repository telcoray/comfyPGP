//! Message decryption (Sequoia).

use std::io::Read;

use anyhow::{Result, anyhow, bail};
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, GoodChecksum, MessageLayer, MessageStructure,
    VerificationError, VerificationHelper,
};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, KeyHandle};
use sequoia_openpgp as openpgp;

use crate::fallback;
use crate::policy::policy;

/// What we could tell about who wrote a decrypted message.
#[derive(Debug, Clone)]
pub enum SignatureCheck {
    NotSigned,
    /// A valid signature by one of the keys we have.
    Good {
        signer: Cert,
    },
    /// Signed by a key we don't have. `issuer` is its fingerprint or
    /// key ID, when the signature says.
    UnknownSigner {
        issuer: Option<String>,
    },
    /// Signed by a key we have, but that key cannot be relied on.
    KeyProblem {
        signer: Cert,
        reason: &'static str,
    },
    /// The signature does not match the message.
    Bad {
        signer: Option<Cert>,
    },
}

impl SignatureCheck {
    /// When a message carries several signatures, the one to show.
    pub(crate) fn rank(&self) -> u8 {
        match self {
            SignatureCheck::NotSigned => 0,
            SignatureCheck::UnknownSigner { .. } => 1,
            SignatureCheck::KeyProblem { .. } => 2,
            SignatureCheck::Bad { .. } => 3,
            SignatureCheck::Good { .. } => 4,
        }
    }
}

#[derive(Debug)]
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    pub signature: SignatureCheck,
}

/// Reads a sender's key to check signatures with. Only the public part
/// is kept, and the key does not need to be usable for encryption.
pub fn load_sender_key(bytes: &[u8]) -> Result<Cert> {
    let cert = Cert::from_bytes(bytes).map_err(|_| anyhow!("This does not contain a PGP key."))?;
    Ok(cert.strip_secret_key_material())
}

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

/// Decrypts an OpenPGP message (armored or binary) and checks its
/// signatures against `senders` (and the user's own key).
pub fn decrypt(
    cert: &Cert,
    passphrase: Option<&str>,
    message: &[u8],
    senders: &[Cert],
) -> Result<Decrypted> {
    let error = match decrypt_with_sequoia(cert, passphrase, message, senders) {
        Ok(decrypted) => return Ok(decrypted),
        Err(e) => e,
    };
    let text = format!("{error:#}");
    // Sequoia 2 cannot read GnuPG's own OCB messages, nor unlock some keys
    // GnuPG protected with a passphrase. rPGP can: see `fallback`.
    let gnupg_ocb = text.contains("AEAD Encrypted Data");
    let cannot_unlock = text.contains(WRONG_PASSPHRASE);
    if !gnupg_ocb && !cannot_unlock {
        return Err(explain(error));
    }
    if !fallback::passphrase_unlocks(cert, passphrase) {
        bail!("Wrong passphrase.");
    }
    fallback::decrypt(cert, passphrase, message, senders).map_err(|e| {
        if format!("{e:#}").contains("missing key") {
            anyhow!("This message was not encrypted for this key.")
        } else {
            anyhow!("Could not decrypt: {e:#}")
        }
    })
}

fn decrypt_with_sequoia(
    cert: &Cert,
    passphrase: Option<&str>,
    message: &[u8],
    senders: &[Cert],
) -> Result<Decrypted> {
    let policy = policy();
    let helper = Helper {
        cert,
        passphrase: passphrase.map(Password::from),
        wrong_passphrase: false,
        senders,
        signature: SignatureCheck::NotSigned,
    };

    let mut decryptor =
        DecryptorBuilder::from_bytes(message).and_then(|b| b.with_policy(&policy, None, helper))?;

    let mut plaintext = Vec::new();
    decryptor.read_to_end(&mut plaintext)?;
    let signature = decryptor.into_helper().signature;
    Ok(Decrypted {
        plaintext,
        signature,
    })
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
    senders: &'a [Cert],
    signature: SignatureCheck,
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        // Our own key too, for messages we signed and encrypted to ourselves.
        let mut certs = self.senders.to_vec();
        certs.push(self.cert.clone().strip_secret_key_material());
        Ok(certs)
    }

    // Never fails: the outcome is shown next to the message instead.
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            let MessageLayer::SignatureGroup { results } = layer else {
                continue;
            };
            for result in results {
                let check = classify(result);
                if check.rank() > self.signature.rank() {
                    self.signature = check;
                }
            }
        }
        Ok(())
    }
}

fn classify(result: std::result::Result<GoodChecksum, VerificationError>) -> SignatureCheck {
    match result {
        Ok(GoodChecksum { ka, .. }) => SignatureCheck::Good {
            signer: ka.cert().clone(),
        },
        Err(VerificationError::MissingKey { sig }) => SignatureCheck::UnknownSigner {
            issuer: sig.get_issuers().first().map(pretty_handle),
        },
        Err(VerificationError::UnboundKey { cert, .. }) => SignatureCheck::KeyProblem {
            signer: cert.clone(),
            reason: "The key that signed this is not properly part of the sender's key.",
        },
        Err(VerificationError::BadKey { ka, error, .. }) => SignatureCheck::KeyProblem {
            signer: ka.cert().clone(),
            reason: key_problem_reason(&error),
        },
        Err(VerificationError::BadSignature { ka, .. }) => SignatureCheck::Bad {
            signer: Some(ka.cert().clone()),
        },
        Err(_) => SignatureCheck::Bad { signer: None },
    }
}

/// A fingerprint grouped in blocks of 4, or a key ID as is.
/// Why a signer's key could not be relied on, in plain words.
pub(crate) fn key_problem_reason(error: &anyhow::Error) -> &'static str {
    let error = format!("{error:#}").to_lowercase();
    if error.contains("revoked") {
        "The sender's key has been revoked."
    } else if error.contains("expired") || error.contains("not alive") {
        "The sender's key had expired when this was signed."
    } else {
        "The sender's key cannot be used for signatures."
    }
}

pub(crate) fn pretty_handle(handle: &KeyHandle) -> String {
    let hex = handle.to_hex();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c))
        .collect::<Vec<_>>()
        .join(" ")
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
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
    use std::io::Write;

    /// Signs `text` with `signer`'s key and, if given, encrypts it to
    /// `recipient`. Unencrypted output is binary, so tests can tamper with it.
    fn signed(signer: &Cert, recipient: Option<&Cert>, text: &[u8]) -> Vec<u8> {
        let p = StandardPolicy::new();
        let signing_key = signer
            .keys()
            .with_policy(&p, None)
            .for_signing()
            .secret()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        let mut out = Vec::new();
        let mut message = Message::new(&mut out);
        if let Some(recipient) = recipient {
            let keys = recipient
                .keys()
                .with_policy(&p, None)
                .for_transport_encryption();
            message = Encryptor::for_recipients(message, keys).build().unwrap();
        }
        let message = Signer::new(message, signing_key).unwrap().build().unwrap();
        let mut w = LiteralWriter::new(message).build().unwrap();
        w.write_all(text).unwrap();
        w.finalize().unwrap();
        out
    }

    fn public(cert: &Cert) -> Cert {
        cert.clone().strip_secret_key_material()
    }

    #[test]
    fn unsigned_messages() {
        let me = new_key(None);
        let msg = encrypt_to(&me, b"hi");
        let d = decrypt(&me, None, &msg, &[]).unwrap();
        assert!(matches!(d.signature, SignatureCheck::NotSigned));
    }

    #[test]
    fn good_signature_with_sender_key() {
        let (me, sender) = (new_key(None), new_key(None));
        let msg = signed(&sender, Some(&me), b"signed hi");
        let d = decrypt(&me, None, &msg, &[public(&sender)]).unwrap();
        assert_eq!(d.plaintext, b"signed hi");
        match d.signature {
            SignatureCheck::Good { signer } => {
                assert_eq!(signer.fingerprint(), sender.fingerprint())
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn signed_by_someone_we_dont_know() {
        let (me, sender) = (new_key(None), new_key(None));
        let msg = signed(&sender, Some(&me), b"who am I");
        let d = decrypt(&me, None, &msg, &[]).unwrap();
        match d.signature {
            SignatureCheck::UnknownSigner {
                issuer: Some(issuer),
            } => {
                let issuer = issuer.replace(' ', "");
                assert!(
                    sender
                        .keys()
                        .any(|k| k.key().fingerprint().to_hex() == issuer
                            || k.key().keyid().to_hex() == issuer)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn our_own_signature_is_recognised() {
        let me = new_key(None);
        let msg = signed(&me, Some(&me), b"note to self");
        let d = decrypt(&me, None, &msg, &[]).unwrap();
        assert!(matches!(d.signature, SignatureCheck::Good { .. }));
    }

    #[test]
    fn tampered_message_has_bad_signature() {
        let (me, sender) = (new_key(None), new_key(None));
        let mut msg = signed(&sender, None, b"pay 10 euro");
        let at = msg.windows(2).position(|w| w == b"10").unwrap();
        msg[at] = b'9';
        let d = decrypt(&me, None, &msg, &[public(&sender)]).unwrap();
        assert_eq!(d.plaintext, b"pay 90 euro");
        assert!(matches!(
            d.signature,
            SignatureCheck::Bad { signer: Some(_) }
        ));
    }

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
            assert_eq!(
                decrypt(&cert, pass, &msg, &[]).unwrap().plaintext,
                b"hello comfy"
            );
        }
    }

    #[test]
    fn friendly_errors() {
        let cert = new_key(Some("secret"));
        let msg = encrypt_to(&cert, b"hi");
        let err = decrypt(&cert, Some("nope"), &msg, &[])
            .unwrap_err()
            .to_string();
        assert_eq!(err, "Wrong passphrase.");

        let other = new_key(None);
        let err = decrypt(&other, None, &msg, &[]).unwrap_err().to_string();
        assert_eq!(err, "This message was not encrypted for this key.");

        let err = decrypt(&cert, Some("secret"), b"hello", &[])
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
                decrypt(&key.cert, Some("secret"), &out.stdout, &[])
                    .unwrap()
                    .plaintext,
                b"from gnupg"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Checks the signature on a message GnuPG signed and encrypted.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_signed_messages() {
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (me, sender) = (new_key(None), new_key(None));
        let files = [("me.asc", public(&me)), ("sender.asc", sender.clone())];
        for (name, cert) in &files {
            let path = dir.join(name);
            std::fs::write(
                &path,
                openpgp::serialize::SerializeInto::to_vec(&cert.as_tsk()).unwrap(),
            )
            .unwrap();
            let ok = Command::new("gpg")
                .arg("--homedir")
                .arg(&dir)
                .args(["--batch", "--import"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                ok.status.success(),
                "{}",
                String::from_utf8_lossy(&ok.stderr)
            );
        }

        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(&dir)
            .args([
                "--batch",
                "--trust-model",
                "always",
                "--armor",
                "--sign",
                "--encrypt",
            ])
            .args(["--local-user", &sender.fingerprint().to_hex()])
            .args(["-r", &me.fingerprint().to_hex()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"signed by gnupg")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let d = decrypt(&me, None, &out.stdout, &[public(&sender)]).unwrap();
        assert_eq!(d.plaintext, b"signed by gnupg");
        assert!(
            matches!(d.signature, SignatureCheck::Good { .. }),
            "{:?}",
            d.signature
        );
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
