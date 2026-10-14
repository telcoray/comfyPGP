# comfyPGP

A friendly OpenPGP app for Windows, made for people who have never used PGP.

comfyPGP creates PGP keys and decrypts messages. Every choice comes with a short,
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
- **Check signatures** on received messages: add the sender's public key to see
  who signed the message and whether it was changed
- Works with GnuPG, Kleopatra, Thunderbird and other OpenPGP apps
- A single `.exe`, no installer and no external DLLs

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
Windows CNG backend (the cryptography built into Windows). comfyPGP does not
implement any cryptography of its own. The interface is built with
[egui](https://github.com/emilk/egui).

## Current limitations

- Signing is not available yet: encrypted messages are not signed.
- Messages in GnuPG's own OCB format cannot be opened yet. GnuPG uses it for
  keys created with GnuPG 2.4+ or Kleopatra; messages to keys created with
  comfyPGP are not affected.

## License

comfyPGP is released under the [MIT License](LICENSE).

It depends on [sequoia-openpgp](https://crates.io/crates/sequoia-openpgp), which
is licensed under the LGPL-2.0-or-later. If you distribute comfyPGP binaries,
the LGPL terms apply to that part.
