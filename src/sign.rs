//! Signing and checking signatures without encryption (Sequoia).

use std::io::{Read, Write};

use anyhow::{Result, anyhow};
use openpgp::crypto::KeyPair;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder,
};
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::{Cert, KeyHandle, armor};
use sequoia_openpgp as openpgp;

use crate::decrypt::{SignatureCheck, classify};
use crate::policy::policy;

/// Signs `text` so it stays readable: the result starts with
/// `-----BEGIN PGP SIGNED MESSAGE-----` and ends with the signature.
pub fn sign_text(signer: KeyPair, text: &str) -> Result<String> {
    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let mut writer = Signer::new(message, signer)?.cleartext().build()?;
    writer.write_all(text.as_bytes())?;
    writer.finalize()?;
    Ok(String::from_utf8(out)?)
}

/// Makes a separate signature for a file. `armor` gives text
/// (`-----BEGIN PGP SIGNATURE-----`), otherwise binary.
pub fn sign_file(signer: KeyPair, data: &[u8], armor: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut message = Message::new(&mut out);
    if armor {
        message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
    }
    let mut writer = Signer::new(message, signer)?.detached().build()?;
    writer.write_all(data)?;
    writer.finalize()?;
    Ok(out)
}

pub struct Verified {
    /// What the signature covers: show this, not the text around it.
    pub content: Vec<u8>,
    pub signature: SignatureCheck,
}

/// Checks a signed text (readable or not), against `certs`.
pub fn verify_text(message: &[u8], certs: &[Cert]) -> Result<Verified> {
    let policy = policy();
    let helper = Helper::new(certs);
    let mut verifier = VerifierBuilder::from_bytes(message)
        .and_then(|b| b.with_policy(&policy, None, helper))
        .map_err(|_| anyhow!("This does not look like a signed message."))?;
    let mut content = Vec::new();
    verifier
        .read_to_end(&mut content)
        .map_err(|_| anyhow!("This does not look like a complete signed message."))?;
    Ok(Verified {
        content,
        signature: verifier.into_helper().signature,
    })
}

/// Checks a file against its separate signature, against `certs`.
pub fn verify_file(data: &[u8], signature: &[u8], certs: &[Cert]) -> Result<SignatureCheck> {
    let policy = policy();
    let helper = Helper::new(certs);
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .and_then(|b| b.with_policy(&policy, None, helper))
        .map_err(|_| anyhow!("The signature file does not contain a PGP signature."))?;
    // A mismatch is reported through the helper, not as an error.
    verifier.verify_bytes(data)?;
    Ok(verifier.into_helper().signature)
}

struct Helper {
    certs: Vec<Cert>,
    signature: SignatureCheck,
}

impl Helper {
    fn new(certs: &[Cert]) -> Self {
        Helper {
            certs: certs.to_vec(),
            signature: SignatureCheck::NotSigned,
        }
    }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }

    // Never fails: the outcome is shown to the user instead.
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    let check = classify(result);
                    if check.rank() > self.signature.rank() {
                        self.signature = check;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Signs `text` inside a (non-cleartext) signed message. Only for tests:
/// the app writes readable signed text instead.
#[cfg(test)]
fn sign_inline(signer: KeyPair, text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = Signer::new(message, signer).unwrap().build().unwrap();
    let mut w = openpgp::serialize::stream::LiteralWriter::new(message)
        .build()
        .unwrap();
    w.write_all(text).unwrap();
    w.finalize().unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{self, Algorithm, KeyRequest};

    fn key() -> Cert {
        keygen::generate(&KeyRequest {
            name: "Signer".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: Some("secret".into()),
        })
        .unwrap()
        .cert
    }

    fn signer(cert: &Cert) -> KeyPair {
        crate::encrypt::signer(cert, Some("secret")).unwrap()
    }

    fn public(cert: &Cert) -> Cert {
        cert.clone().strip_secret_key_material()
    }

    fn is_good_by(check: &SignatureCheck, cert: &Cert) -> bool {
        matches!(check, SignatureCheck::Good { signer } if signer.fingerprint() == cert.fingerprint())
    }

    #[test]
    fn signed_text_verifies_and_stays_readable() {
        let me = key();
        let text = "Hello,\r\nthis is from me.  \nBye";
        let signed = sign_text(signer(&me), text).unwrap();
        assert!(signed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(signed.contains("this is from me."));

        let v = verify_text(signed.as_bytes(), &[public(&me)]).unwrap();
        assert!(is_good_by(&v.signature, &me), "{:?}", v.signature);
        assert!(
            String::from_utf8(v.content)
                .unwrap()
                .contains("this is from me.")
        );

        let v = verify_text(signed.as_bytes(), &[]).unwrap();
        assert!(matches!(
            v.signature,
            SignatureCheck::UnknownSigner { issuer: Some(_) }
        ));
    }

    #[test]
    fn changed_text_is_caught() {
        let me = key();
        let signed = sign_text(signer(&me), "Pay Mario 10 euro").unwrap();
        let forged = signed.replace("10 euro", "90 euro");
        let v = verify_text(forged.as_bytes(), &[public(&me)]).unwrap();
        assert!(
            matches!(v.signature, SignatureCheck::Bad { .. }),
            "{:?}",
            v.signature
        );
    }

    #[test]
    fn inline_signed_messages_verify_too() {
        let me = key();
        let msg = sign_inline(signer(&me), b"inline");
        let v = verify_text(&msg, &[public(&me)]).unwrap();
        assert_eq!(v.content, b"inline");
        assert!(is_good_by(&v.signature, &me));
    }

    #[test]
    fn file_signatures() {
        let me = key();
        let data = vec![7u8; 5000];
        for armor in [true, false] {
            let sig = sign_file(signer(&me), &data, armor).unwrap();
            assert_eq!(sig.starts_with(b"-----BEGIN PGP SIGNATURE-----"), armor);
            let check = verify_file(&data, &sig, &[public(&me)]).unwrap();
            assert!(is_good_by(&check, &me), "{check:?}");

            let mut changed = data.clone();
            changed[100] = 8;
            let check = verify_file(&changed, &sig, &[public(&me)]).unwrap();
            assert!(matches!(check, SignatureCheck::Bad { .. }), "{check:?}");

            let check = verify_file(&data, &sig, &[]).unwrap();
            assert!(
                matches!(check, SignatureCheck::UnknownSigner { .. }),
                "{check:?}"
            );
        }
    }

    #[test]
    fn not_a_signature() {
        assert!(verify_text(b"just some text", &[]).is_err());
        assert!(verify_file(b"data", b"not a signature", &[]).is_err());
    }

    /// GnuPG checks what comfyPGP signs, and comfyPGP checks what GnuPG signs.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_interop() {
        use openpgp::serialize::SerializeInto;
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!("comfypgp-sv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let me = key();
        let gpg = |args: &[&str], stdin: &[u8]| {
            let mut child = Command::new("gpg")
                .arg("--homedir")
                .arg(&dir)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "secret",
                ])
                .args(["--trust-model", "always", "--status-fd", "2"])
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(stdin).unwrap();
            child.wait_with_output().unwrap()
        };
        let key_file = dir.join("me.pgp");
        std::fs::write(&key_file, me.as_tsk().to_vec().unwrap()).unwrap();
        assert!(
            gpg(&["--import", key_file.to_str().unwrap()], b"")
                .status
                .success()
        );

        // comfyPGP signs, GnuPG checks.
        let signed = sign_text(signer(&me), "Readable and signed\nline two").unwrap();
        let out = gpg(&["--verify"], signed.as_bytes());
        let status = String::from_utf8_lossy(&out.stderr);
        assert!(status.contains("[GNUPG:] GOODSIG"), "{status}");

        let data_file = dir.join("data.bin");
        std::fs::write(&data_file, b"release file").unwrap();
        for armor in [true, false] {
            let sig_file = dir.join(if armor {
                "data.bin.asc"
            } else {
                "data.bin.sig"
            });
            std::fs::write(
                &sig_file,
                sign_file(signer(&me), b"release file", armor).unwrap(),
            )
            .unwrap();
            let out = gpg(
                &[
                    "--verify",
                    sig_file.to_str().unwrap(),
                    data_file.to_str().unwrap(),
                ],
                b"",
            );
            let status = String::from_utf8_lossy(&out.stderr);
            assert!(
                status.contains("[GNUPG:] GOODSIG"),
                "armor={armor}: {status}"
            );
        }

        // GnuPG signs, comfyPGP checks.
        let fpr = me.fingerprint().to_hex();
        let clearsigned = gpg(&["--local-user", &fpr, "--clearsign"], b"from gnupg\n").stdout;
        let v = verify_text(&clearsigned, &[public(&me)]).unwrap();
        assert!(is_good_by(&v.signature, &me), "{:?}", v.signature);
        assert!(String::from_utf8(v.content).unwrap().contains("from gnupg"));

        let detached = gpg(&["--local-user", &fpr, "--armor", "--detach-sign"], b"blob").stdout;
        let check = verify_file(b"blob", &detached, &[public(&me)]).unwrap();
        assert!(is_good_by(&check, &me), "{check:?}");

        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&dir)
            .args(["--kill", "gpg-agent"])
            .output();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
