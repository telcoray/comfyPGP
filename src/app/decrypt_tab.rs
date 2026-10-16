//! The Decrypt tab.

use super::*;

impl ComfyApp {
    pub(super) fn decrypt_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Encrypted message");
        if let Some((name, _)) = &self.dec_file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {name}"));
                clear = ui.small_button("✖").on_hover_text("Remove file").clicked();
            });
            if clear {
                self.dec_file = None;
                self.message_changed();
            }
        } else {
            let edit = ui.add(
                egui::TextEdit::multiline(&mut self.dec_message)
                    .hint_text("Paste the message here. It starts with -----BEGIN PGP MESSAGE-----")
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if edit.changed() {
                self.message_changed();
            }
        }
        if ui.button("📂 Open encrypted file…").clicked() {
            self.open_encrypted_file();
        }

        ui.add_space(SECTION_GAP);
        self.your_key_ui(ui);
        ui.add_space(SECTION_GAP);
        self.sender_ui(ui);

        let needs_passphrase = self.dec_key.as_ref().is_some_and(decrypt::needs_passphrase);
        if needs_passphrase {
            ui.add_space(SECTION_GAP);
            form_grid("dec-passphrase").show(ui, |ui| {
                ui.label("Passphrase");
                ui.add(egui::TextEdit::singleline(&mut self.dec_passphrase).password(true));
                ui.end_row();
            });
        }

        ui.add_space(SECTION_GAP);
        let has_message = self.dec_file.is_some() || !self.dec_message.trim().is_empty();
        let ready = self.dec_key.is_some()
            && has_message
            && (!needs_passphrase || !self.dec_passphrase.is_empty());
        let button = egui::Button::new(RichText::new("🔓  Decrypt").size(16.0));
        if ui.add_enabled(ready, button).clicked() {
            self.run_decrypt(needs_passphrase);
        }

        self.decrypt_result_ui(ui);
    }

    fn your_key_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Your key");
        let selected = match &self.dec_key {
            Some(cert) => self.display_name(cert),
            None if self.store.my_keys.is_empty() => "No saved keys".into(),
            None => "Choose one of your keys…".into(),
        };
        let mut picked = None;
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(!self.store.my_keys.is_empty(), |ui| {
                egui::ComboBox::from_id_salt("dec-key")
                    .selected_text(selected)
                    .width(220.0)
                    .show_ui(ui, |ui| {
                        for entry in &self.store.my_keys {
                            let is_current = self
                                .dec_key
                                .as_ref()
                                .is_some_and(|c| c.fingerprint() == entry.cert.fingerprint());
                            if ui.selectable_label(is_current, &entry.name).clicked() {
                                picked = Some(entry.cert.clone());
                            }
                        }
                    });
            });
            if ui.small_button("📂 Open secret key file…").clicked() {
                self.open_secret_key();
            }
        });
        if let Some(cert) = picked {
            self.use_key(cert, false);
        }
        if let Some(cert) = &self.dec_key {
            ui.label(RichText::new(key_details(cert)).weak());
        }
        if self.dec_key_auto {
            ui.colored_label(
                GOOD_COLOR,
                "✔ Chosen automatically: this message is for this key.",
            );
        } else if self.dec_no_match {
            warning(
                ui,
                "This message was not encrypted for any of your saved keys. If you have the \
                 right key in a file, open it.",
            );
        }
        explainer(
            ui,
            "Which key do I need?",
            &[
                "People lock messages for you with your public key. Only the matching \
                 secret key can open them. comfyPGP finds it among your saved keys by itself.",
                "A public key will not work here, and neither will someone else's key.",
            ],
        );
    }

    /// Picks the key to decrypt with. `auto` means it was matched from
    /// the message's recipients.
    fn use_key(&mut self, cert: Cert, auto: bool) {
        let same = self
            .dec_key
            .as_ref()
            .is_some_and(|c| c.fingerprint() == cert.fingerprint());
        if !same {
            self.dec_passphrase.clear();
        }
        self.dec_key = Some(cert);
        self.dec_key_auto = auto;
        self.dec_no_match = false;
        self.dec_output = None;
    }

    /// The message changed: forget the old result and look for the key
    /// it was encrypted for.
    fn message_changed(&mut self) {
        self.dec_output = None;
        self.dec_key_auto = false;
        self.dec_no_match = false;
        let message = match &self.dec_file {
            Some((_, bytes)) => bytes.clone(),
            None => self.dec_message.trim().as_bytes().to_vec(),
        };
        let recipients = decrypt::recipients(&message);
        if recipients.is_empty() {
            return;
        }
        let found = self
            .store
            .my_keys
            .iter()
            .find(|e| decrypt::is_for(&e.cert, &recipients))
            .map(|e| e.cert.clone());
        match found {
            Some(cert) => self.use_key(cert, true),
            None => {
                let current_fits = self
                    .dec_key
                    .as_ref()
                    .is_some_and(|c| decrypt::is_for(c, &recipients));
                self.dec_no_match = !current_fits && !self.store.my_keys.is_empty();
            }
        }
    }

    fn sender_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Sender (optional)");
        if self.dec_senders.is_empty() {
            ui.label(
                RichText::new(
                    "Signatures from your contacts are checked automatically. Add a key here \
                     only for someone who is not in your contacts.",
                )
                .weak(),
            );
        }
        let mut remove = None;
        for (i, cert) in self.dec_senders.iter().enumerate() {
            if cert_row(ui, &self.display_name(cert), cert) {
                remove = Some(i);
            }
        }
        if let Some(i) = remove {
            self.dec_senders.remove(i);
            self.dec_output = None;
            self.dec_sender_notice = Status::None;
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("📂 Open public key file…").clicked()
                && let Some(bytes) = pick_key_file("Open the sender's public key")
            {
                self.add_sender_from(bytes);
            }
            if ui.button("📋 Paste public key").clicked() {
                self.add_sender_from(clipboard_key());
            }
        });
        notice_ui(ui, &self.dec_sender_notice);
        explainer(
            ui,
            "Why add the sender's key?",
            &[
                "If the sender signed the message, their public key lets comfyPGP check \
                 that they really wrote it and that nobody changed it on the way.",
                "Without it you can still read the message, but you cannot be sure who \
                 sent it.",
            ],
        );
    }

    fn add_sender_from(&mut self, bytes: anyhow::Result<Vec<u8>>) {
        let cert = match bytes.and_then(|bytes| decrypt::load_sender_key(&bytes)) {
            Ok(cert) => cert,
            Err(e) => {
                self.dec_sender_notice = Status::Error(format!("{e:#}"));
                return;
            }
        };
        if self
            .dec_senders
            .iter()
            .any(|c| c.fingerprint() == cert.fingerprint())
        {
            self.dec_sender_notice = Status::Info("This key is already in the list.".into());
            return;
        }
        self.dec_senders.push(cert);
        self.dec_sender_notice = Status::None;
        // The shown result no longer matches the keys: decrypt again.
        if self.dec_output.take().is_some() {
            self.dec_sender_notice =
                Status::Info("Key added. Click Decrypt again to check the signature.".into());
        }
    }

    fn decrypt_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(decrypted) = &self.dec_output else {
            return;
        };
        let output = &decrypted.plaintext;

        ui.separator();
        ui.heading("Decrypted message");
        let name = |cert: &Cert| self.display_name(cert);
        signature_banner(ui, &decrypted.signature, &name);
        // A signer we know only from a key added here: offer to save them.
        let mut save_signer = None;
        if let SignatureCheck::Good { signer } | SignatureCheck::KeyProblem { signer, .. } =
            &decrypted.signature
            && self.store.name_for(&signer.fingerprint()).is_none()
            && ui.button("👤 Save the sender to Contacts").clicked()
        {
            save_signer = Some(signer.clone());
        }
        ui.add_space(6.0);
        let text = std::str::from_utf8(output).ok();
        let mut copy = false;
        let mut save = false;
        ui.horizontal(|ui| {
            if text.is_some() {
                copy = ui.button("📋 Copy").clicked();
            }
            save = ui.button("💾 Save…").clicked();
        });
        match text {
            Some(text) => {
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut &*text).desired_width(f32::INFINITY));
                    });
            }
            None => {
                ui.label(format!(
                    "The message contains a file ({} KB). Save it to open it.",
                    output.len().div_ceil(1024)
                ));
            }
        }

        if copy && let Some(text) = text {
            let text = text.to_owned();
            self.status = match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
                Ok(()) => Status::Info("Decrypted message copied to clipboard.".into()),
                Err(e) => Status::Error(format!("Could not copy: {e}")),
            };
        }
        if save {
            self.save_decrypted();
        }
        if let Some(signer) = save_signer {
            self.offer_new_contact(signer);
        }
    }

    fn open_secret_key(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open your secret key")
            .add_filter(
                "PGP key (.asc, .txt, .gpg, .key)",
                &["asc", "txt", "gpg", "key"],
            )
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        let result = std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| decrypt::load_secret_key(&bytes));
        match result {
            Ok(cert) => {
                self.use_key(cert, false);
                self.status = Status::None;
            }
            Err(e) => self.status = Status::Error(format!("{e:#}")),
        }
    }

    fn open_encrypted_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open an encrypted message")
            .add_filter(
                "PGP message (.asc, .txt, .gpg, .pgp)",
                &["asc", "txt", "gpg", "pgp"],
            )
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.status = Status::Error(format!("Could not open the file: {e}"));
                return;
            }
        };
        self.dec_output = None;
        self.status = Status::None;
        // Text messages go in the box, so people can see what they opened.
        match String::from_utf8(bytes) {
            Ok(text) if text.contains("-----BEGIN PGP") => {
                self.dec_file = None;
                self.dec_message = text;
            }
            Ok(text) => self.dec_file = Some((file_name(&path), text.into_bytes())),
            Err(e) => self.dec_file = Some((file_name(&path), e.into_bytes())),
        }
        self.message_changed();
    }

    /// Keys whose signatures we can check: contacts, the user's own keys,
    /// and any added just for this message.
    fn known_signers(&self) -> Vec<Cert> {
        let mut all = self.dec_senders.clone();
        all.extend(self.store.contacts.iter().map(|e| e.cert.clone()));
        all.extend(
            self.store
                .my_keys
                .iter()
                .map(|e| e.cert.clone().strip_secret_key_material()),
        );
        all
    }

    fn run_decrypt(&mut self, needs_passphrase: bool) {
        let Some(cert) = &self.dec_key else { return };
        let message = match &self.dec_file {
            Some((_, bytes)) => bytes.as_slice(),
            None => self.dec_message.trim().as_bytes(),
        };
        let passphrase = needs_passphrase.then_some(self.dec_passphrase.as_str());
        match decrypt::decrypt(cert, passphrase, message, &self.known_signers()) {
            Ok(decrypted) => {
                self.dec_output = Some(decrypted);
                self.status = Status::Info("Message decrypted.".into());
            }
            Err(e) => {
                self.dec_output = None;
                self.status = Status::Error(format!("{e:#}"));
            }
        }
    }

    fn save_decrypted(&mut self) {
        let Some(output) = self.dec_output.as_ref().map(|d| &d.plaintext) else {
            return;
        };
        // "letter.txt.gpg" -> "letter.txt"; pasted text -> "decrypted.txt".
        let suggested = self
            .dec_file
            .as_ref()
            .and_then(|(name, _)| Path::new(name).file_stem())
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "decrypted.txt".into());
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save decrypted message")
            .set_file_name(suggested)
            .save_file()
        else {
            return;
        };
        self.status = match std::fs::write(&path, output) {
            Ok(()) => Status::Info(format!("Saved to {}", path.display())),
            Err(e) => Status::Error(format!("Could not save: {e}")),
        };
    }
}
