<p align="center"><img src="assets/icon-256.png" alt="comfyPGP logo" width="128"></p>

# comfyPGP

A friendly OpenPGP app for Windows, made for people who have never used PGP.

comfyPGP creates keys, encrypts, decrypts, signs and checks signatures, and keeps
your keys and contacts in an address book. Every choice comes with a short,
plain-language explanation, so you never have to guess what an option means.

## Features

- **Create a key** in a few clicks:
  - **Modern** (Ed25519 / Curve25519, recommended) or **Classic** (RSA 4096) keys
  - Name/nickname and email are optional, with advice on when to use which
  - Expiry of 1, 2, 3 or 5 years, or never
  - Optional passphrase to protect the secret key
- **Export** the public key, secret key and revocation certificate as
  `.asc`, `.txt` or binary `.gpg`, or copy the public key to the clipboard
- **Encrypt** a message or a file for one or more people, using their public keys
- **Decrypt** messages: paste the text or open a file, use your secret key,
  then copy or save the result
- **Sign** what you encrypt with one of your keys, so the recipient knows it is from you
- **Check signatures** on received messages: see who signed the message and whether
  it was changed
- **Sign & Verify** without encrypting: readable signed texts, and separate signature
  files for documents or programs, compatible with GnuPG
- **Address book**: your own keys and your contacts, each with a name you choose
- Works with GnuPG, Kleopatra, Thunderbird and other OpenPGP apps
- A single `.exe`, no installer and no external DLLs

## Verifying downloads

From version 0.5.1, releases are signed with the **Telcoray Github** key, which
signs the releases of all Telcoray projects:

```
B7E1 8129 21B3 2E65 3349  581F C972 2CF9 41EA 4C91
```

Its public key is [telcoray-github.asc](telcoray-github.asc). The signature is
the `.asc` file next to each `.exe` on the release page.

**With comfyPGP:** add `telcoray-github.asc` in Contacts, then go to
Sign & Verify → Verify → "Check a file instead…" and choose the `.exe`. Its
signature next to it is found automatically. You should see
✔ **Signed by Telcoray Github**.

**With GnuPG:**

```
gpg --import telcoray-github.asc
gpg --verify comfyPGP-0.5.1-windows-x64.exe.asc comfyPGP-0.5.1-windows-x64.exe
```

Check that the fingerprint above matches the one comfyPGP or GnuPG shows.

**Version 0.5.0** was signed with an earlier key, **comfyPGP releases**
(`9B31 82EF 6973 F85E AB90  7814 4C5E 75B8 AEFB D74C`,
[comfyPGP-releases-2026-10.asc](comfyPGP-releases-2026-10.asc)). That key was
retired in November 2026 because its passphrase was lost: it was not
compromised, and its signature on 0.5.0 is still valid. It will not sign
anything else, and it expires on 15 October 2028.

## Build

You need [Rust](https://rustup.rs/) (stable, MSVC toolchain).

```
cargo build --release
```

The app is created at `target\release\comfypgp.exe`.

To run the tests, including the ones that check compatibility with an installed GnuPG:

```
cargo test -- --include-ignored
```

## How it works

The OpenPGP logic comes from [Sequoia PGP](https://sequoia-pgp.org/), using its
Windows CNG backend (the cryptography built into Windows). Keys and messages
made by GnuPG 2.4+ or Kleopatra sometimes use formats Sequoia cannot handle
(GnuPG's own OCB encryption, and some passphrase-protected keys): for those,
[rPGP](https://github.com/rpgp/rpgp) unlocks the key and removes the encryption,
while signatures are still checked by Sequoia. comfyPGP does not implement any
cryptography of its own. The interface is built with
[egui](https://github.com/emilk/egui).

## Current limitations

- GnuPG 2.5 (and Kleopatra) cannot use a comfyPGP secret key that has no passphrase:
  it imports it, but then cannot decrypt with it. Keys with a passphrase work: use
  "Set passphrase…" in My keys, then save the secret key again and import that.

## License

comfyPGP is released under the [MIT License](LICENSE).

It depends on [sequoia-openpgp](https://crates.io/crates/sequoia-openpgp), which
is licensed under the LGPL-2.0-or-later. If you distribute comfyPGP binaries,
the LGPL terms apply to that part. It also uses [rPGP](https://crates.io/crates/pgp)
(MIT or Apache-2.0).
