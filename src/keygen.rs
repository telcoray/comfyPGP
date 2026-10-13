//! OpenPGP key generation and export (Sequoia).

use std::time::Duration;

use anyhow::{Result, bail};
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::packet::Signature;
use openpgp::serialize::{Marshal, SerializeInto};
use openpgp::types::Features;
use openpgp::{Packet, Profile, armor};
use sequoia_openpgp as openpgp;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Cv25519,
    Rsa4096,
}

impl Algorithm {
    fn suite(self) -> CipherSuite {
        match self {
            Algorithm::Cv25519 => CipherSuite::Cv25519,
            Algorithm::Rsa4096 => CipherSuite::RSA4k,
        }
    }
}

pub struct KeyRequest {
    pub name: String,
    pub email: String,
    pub algorithm: Algorithm,
    /// `None` = the key never expires.
    pub validity: Option<Duration>,
    /// `None` = the secret key is left unprotected.
    pub passphrase: Option<String>,
}

pub struct GeneratedKey {
    pub cert: Cert,
    pub revocation: Signature,
}

/// Builds the User ID in the classic `Name <email>` format.
/// Returns `None` if both fields are empty.
pub fn user_id(name: &str, email: &str) -> Option<String> {
    match (name.trim(), email.trim()) {
        ("", "") => None,
        (n, "") => Some(n.to_string()),
        ("", e) => Some(format!("<{e}>")),
        (n, e) => Some(format!("{n} <{e}>")),
    }
}

pub fn generate(req: &KeyRequest) -> Result<GeneratedKey> {
    let mut builder = CertBuilder::new()
        // v4 keys that only advertise SEIPDv1: GnuPG and Kleopatra cannot
        // read SEIPDv2 (RFC 9580) messages, which Sequoia would otherwise
        // invite senders to use.
        .set_profile(Profile::RFC4880)?
        .set_features(Features::empty().set_seipdv1())?
        .set_cipher_suite(req.algorithm.suite())
        .set_validity_period(req.validity)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey();

    if let Some(uid) = user_id(&req.name, &req.email) {
        builder = builder.add_userid(uid);
    }

    if let Some(pass) = &req.passphrase {
        if pass.is_empty() {
            bail!("empty passphrase");
        }
        builder = builder.set_password(Some(Password::from(pass.as_str())));
    }

    let (cert, revocation) = builder.generate()?;
    Ok(GeneratedKey { cert, revocation })
}

/// What to export.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Part {
    Public,
    Secret,
    Revocation,
}

/// File format: text (ASCII armor, for .asc and .txt) or binary (.gpg).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    Armored,
    Binary,
}

pub fn export(key: &GeneratedKey, part: Part, encoding: Encoding) -> Result<Vec<u8>> {
    Ok(match (part, encoding) {
        (Part::Public, Encoding::Armored) => key.cert.armored().to_vec()?,
        (Part::Public, Encoding::Binary) => key.cert.to_vec()?,
        (Part::Secret, Encoding::Armored) => key.cert.as_tsk().armored().to_vec()?,
        (Part::Secret, Encoding::Binary) => key.cert.as_tsk().to_vec()?,
        (Part::Revocation, encoding) => {
            // Like GnuPG's .rev files: just the revocation signature inside
            // a "PUBLIC KEY" block, importable with `gpg --import`.
            let packet = Packet::from(key.revocation.clone());
            match encoding {
                Encoding::Binary => packet.to_vec()?,
                Encoding::Armored => {
                    let mut buf = Vec::new();
                    let headers = [(
                        "Comment",
                        "Revocation certificate. Import it ONLY to revoke the key.",
                    )];
                    let mut w =
                        armor::Writer::with_headers(&mut buf, armor::Kind::PublicKey, headers)?;
                    packet.serialize(&mut w)?;
                    w.finalize()?;
                    buf
                }
            }
        }
    })
}

/// Fingerprint grouped in blocks of 4, the way GnuPG shows it.
pub fn pretty_fingerprint(cert: &Cert) -> String {
    let hex = cert.fingerprint().to_hex();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::parse::Parse;

    fn request(passphrase: Option<&str>, validity: Option<Duration>) -> KeyRequest {
        KeyRequest {
            name: "Test".into(),
            email: "test@example.org".into(),
            algorithm: Algorithm::Cv25519,
            validity,
            passphrase: passphrase.map(String::from),
        }
    }

    #[test]
    fn user_id_formats() {
        assert_eq!(user_id("", " "), None);
        assert_eq!(user_id("Anna", ""), Some("Anna".into()));
        assert_eq!(user_id("", "a@b.c"), Some("<a@b.c>".into()));
        assert_eq!(user_id("Anna", "a@b.c"), Some("Anna <a@b.c>".into()));
    }

    #[test]
    fn no_expiry_no_passphrase_roundtrip() {
        let key = generate(&request(None, None)).unwrap();
        let p = openpgp::policy::StandardPolicy::new();
        let vc = key.cert.with_policy(&p, None).unwrap();
        assert_eq!(vc.primary_key().key_expiration_time(), None);
        assert!(
            key.cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap()
                .secret()
                .is_encrypted()
                == false
        );

        for enc in [Encoding::Armored, Encoding::Binary] {
            let public = Cert::from_bytes(&export(&key, Part::Public, enc).unwrap()).unwrap();
            assert!(!public.is_tsk());
            let secret = Cert::from_bytes(&export(&key, Part::Secret, enc).unwrap()).unwrap();
            assert!(secret.is_tsk());
            assert_eq!(public.fingerprint(), key.cert.fingerprint());
        }
    }

    #[test]
    fn gnupg_compatible_format() {
        let key = generate(&request(None, None)).unwrap();
        assert_eq!(key.cert.primary_key().key().version(), 4);
        let p = openpgp::policy::StandardPolicy::new();
        let features = key.cert.with_policy(&p, None).unwrap().features().unwrap();
        assert!(features.supports_seipdv1());
        assert!(!features.supports_seipdv2());
    }

    #[test]
    fn passphrase_encrypts_secret() {
        let key = generate(&request(Some("secret"), Some(Duration::from_secs(86400)))).unwrap();
        let k = key
            .cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap();
        assert!(k.secret().is_encrypted());
    }

    #[test]
    fn no_user_id() {
        let mut req = request(None, None);
        req.name.clear();
        req.email.clear();
        let key = generate(&req).unwrap();
        assert_eq!(key.cert.userids().count(), 0);
    }

    /// Checks that GnuPG imports the exported keys.
    /// Requires `gpg` on the PATH: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn gnupg_interop() {
        use std::process::Command;

        let dir = std::env::temp_dir().join(format!("comfypgp-test-{}", std::process::id()));
        let home = dir.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        let gpg = |args: &[&str]| {
            let out = Command::new("gpg")
                .arg("--homedir")
                .arg(&home)
                .args([
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "secret",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        };

        for (alg, ext, enc) in [
            (Algorithm::Cv25519, "asc", Encoding::Armored),
            (Algorithm::Rsa4096, "gpg", Encoding::Binary),
        ] {
            let mut req = request(Some("secret"), None);
            req.algorithm = alg;
            let key = generate(&req).unwrap();
            let fpr = key.cert.fingerprint().to_hex();

            for part in [Part::Public, Part::Secret] {
                let path = dir.join(format!("{fpr}-{part:?}.{ext}"));
                std::fs::write(&path, export(&key, part, enc).unwrap()).unwrap();
                gpg(&["--import", path.to_str().unwrap()]);
            }
            let listing = gpg(&["--with-colons", "--list-secret-keys", &fpr]);
            assert!(listing.contains(&fpr));

            let rev = dir.join(format!("{fpr}.rev.asc"));
            std::fs::write(
                &rev,
                export(&key, Part::Revocation, Encoding::Armored).unwrap(),
            )
            .unwrap();
            gpg(&["--import", rev.to_str().unwrap()]);
            let listing = gpg(&["--with-colons", "--list-keys", &fpr]);
            assert!(listing.contains("pub:r:"), "key not revoked:\n{listing}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revocation_exports() {
        let key = generate(&request(None, None)).unwrap();
        let armored = export(&key, Part::Revocation, Encoding::Armored).unwrap();
        let text = String::from_utf8(armored).unwrap();
        assert!(text.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }
}
