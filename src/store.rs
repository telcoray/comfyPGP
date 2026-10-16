//! The address book: the user's own keys and their contacts, each with a
//! name the user chose. Saved as one JSON file in %APPDATA%\comfyPGP.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use openpgp::{Cert, Fingerprint};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};

pub struct Entry {
    pub name: String,
    pub cert: Cert,
}

pub struct Store {
    /// The user's own keys, with their secret parts (locked if they have
    /// a passphrase).
    pub my_keys: Vec<Entry>,
    /// Other people's public keys.
    pub contacts: Vec<Entry>,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct StoredBook {
    version: u32,
    my_keys: Vec<StoredEntry>,
    contacts: Vec<StoredEntry>,
}

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    name: String,
    /// The key, ASCII armored.
    key: String,
}

/// `%APPDATA%\comfyPGP\address-book.json`.
pub fn default_path() -> Result<PathBuf> {
    let appdata =
        std::env::var_os("APPDATA").ok_or_else(|| anyhow!("Cannot find your AppData folder."))?;
    Ok(PathBuf::from(appdata)
        .join("comfyPGP")
        .join("address-book.json"))
}

impl Store {
    /// Loads the address book from `path`, or starts an empty one.
    ///
    /// A file that cannot be read is renamed and set aside, never
    /// overwritten: the returned message says where it went.
    pub fn load(path: PathBuf) -> (Store, Option<String>) {
        let mut store = Store {
            my_keys: Vec::new(),
            contacts: Vec::new(),
            path,
        };
        let bytes = match std::fs::read(&store.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (store, None),
            Err(e) => {
                let msg = format!("Could not read your address book: {e}");
                return (store, Some(msg));
            }
        };
        match parse(&bytes) {
            Ok((my_keys, contacts)) => {
                store.my_keys = my_keys;
                store.contacts = contacts;
                (store, None)
            }
            Err(e) => {
                let msg = match set_aside(&store.path) {
                    Ok(moved) => format!(
                        "Your address book could not be read ({e:#}). It was kept as {} \
                         and comfyPGP started a new one.",
                        moved.display()
                    ),
                    Err(move_err) => format!(
                        "Your address book could not be read ({e:#}), and could not be \
                         set aside ({move_err:#})."
                    ),
                };
                (store, Some(msg))
            }
        }
    }

    /// Writes the address book. The file is replaced only once the new
    /// version is fully written.
    pub fn save(&self) -> Result<()> {
        let book = StoredBook {
            version: 1,
            my_keys: self
                .my_keys
                .iter()
                .map(|e| stored(&e.name, e.cert.as_tsk().armored().to_vec()))
                .collect::<Result<_>>()?,
            contacts: self
                .contacts
                .iter()
                .map(|e| stored(&e.name, e.cert.armored().to_vec()))
                .collect::<Result<_>>()?,
        };
        let json = serde_json::to_vec_pretty(&book)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).context("Could not create the comfyPGP folder")?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).context("Could not save the address book")?;
        std::fs::rename(&tmp, &self.path).context("Could not save the address book")?;
        Ok(())
    }

    /// Adds one of the user's own keys. It must include the secret key.
    pub fn add_my_key(&mut self, name: &str, cert: Cert) -> Result<()> {
        if !cert.is_tsk() {
            bail!("This is a public key. Add it in Contacts instead.");
        }
        let name = valid_name(name)?;
        if let Some(existing) = self.name_for(&cert.fingerprint()) {
            bail!("This key is already saved as \"{existing}\".");
        }
        self.my_keys.push(Entry { name, cert });
        Ok(())
    }

    /// Adds a contact. Only the public part of the key is kept.
    pub fn add_contact(&mut self, name: &str, cert: Cert) -> Result<()> {
        let name = valid_name(name)?;
        if let Some(existing) = self.name_for(&cert.fingerprint()) {
            bail!("This key is already saved as \"{existing}\".");
        }
        self.contacts.push(Entry {
            name,
            cert: cert.strip_secret_key_material(),
        });
        Ok(())
    }

    /// The name the user gave to this key, among their keys and contacts.
    pub fn name_for(&self, fingerprint: &Fingerprint) -> Option<&str> {
        self.my_keys
            .iter()
            .chain(&self.contacts)
            .find(|e| &e.cert.fingerprint() == fingerprint)
            .map(|e| e.name.as_str())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn valid_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Give it a name first.");
    }
    Ok(name.to_string())
}

fn stored(name: &str, armored: openpgp::Result<Vec<u8>>) -> Result<StoredEntry> {
    Ok(StoredEntry {
        name: name.to_string(),
        key: String::from_utf8(armored?)?,
    })
}

fn parse(bytes: &[u8]) -> Result<(Vec<Entry>, Vec<Entry>)> {
    let book: StoredBook = serde_json::from_slice(bytes)?;
    if book.version != 1 {
        bail!("it was made by a newer comfyPGP (version {})", book.version);
    }
    // One unreadable key makes the whole file suspect: better to set it
    // aside than to silently drop that key on the next save.
    let load = |entries: Vec<StoredEntry>| -> Result<Vec<Entry>> {
        entries
            .into_iter()
            .map(|e| {
                let cert = Cert::from_bytes(e.key.as_bytes())
                    .with_context(|| format!("the key \"{}\" is damaged", e.name))?;
                Ok(Entry { name: e.name, cert })
            })
            .collect()
    };
    Ok((load(book.my_keys)?, load(book.contacts)?))
}

/// Renames a broken address book so it is not overwritten.
fn set_aside(path: &Path) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let moved = path.with_extension(format!("broken-{stamp}.json"));
    std::fs::rename(path, &moved)?;
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{self, Algorithm, KeyRequest};

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("comfypgp-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("address-book.json")
    }

    fn key(passphrase: Option<&str>) -> Cert {
        keygen::generate(&KeyRequest {
            name: "Test".into(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            validity: None,
            passphrase: passphrase.map(String::from),
        })
        .unwrap()
        .cert
    }

    #[test]
    fn saves_and_loads_names_and_keys() {
        let path = temp_path("roundtrip");
        let (mut store, warning) = Store::load(path.clone());
        assert!(warning.is_none());
        let (work, friend) = (key(Some("secret")), key(None));
        store.add_my_key("lavoro", work.clone()).unwrap();
        store.add_contact("  Mario  ", friend.clone()).unwrap();
        store.save().unwrap();

        let (loaded, warning) = Store::load(path.clone());
        assert!(warning.is_none());
        assert_eq!(loaded.my_keys[0].name, "lavoro");
        assert!(loaded.my_keys[0].cert.is_tsk());
        assert!(crate::decrypt::needs_passphrase(&loaded.my_keys[0].cert));
        assert_eq!(loaded.contacts[0].name, "Mario");
        assert!(!loaded.contacts[0].cert.is_tsk());
        assert_eq!(loaded.name_for(&friend.fingerprint()), Some("Mario"));
        assert_eq!(loaded.name_for(&work.fingerprint()), Some("lavoro"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_duplicates_public_keys_and_empty_names() {
        let (mut store, _) = Store::load(temp_path("rules"));
        let k = key(None);
        store.add_my_key("amici", k.clone()).unwrap();
        let err = store
            .add_contact("Again", k.clone())
            .unwrap_err()
            .to_string();
        assert!(err.contains("already saved as \"amici\""), "{err}");
        let err = store
            .add_my_key("x", key(None).strip_secret_key_material())
            .unwrap_err()
            .to_string();
        assert!(err.contains("public key"), "{err}");
        assert!(store.add_contact("   ", key(None)).is_err());
    }

    #[test]
    fn broken_file_is_set_aside_not_overwritten() {
        let path = temp_path("broken");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        let (store, warning) = Store::load(path.clone());
        assert!(warning.unwrap().contains("could not be read"));
        assert!(store.my_keys.is_empty());
        assert!(!path.exists());
        let kept: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains("broken-"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read(&kept[0]).unwrap(), b"{ not json");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
