//! The Encrypt tab.

use super::*;

impl ComfyApp {
    pub(super) fn encrypt_ui(&mut self, ui: &mut egui::Ui) {
        self.sender_key_ui(ui);
        ui.add_space(SECTION_GAP);
        self.recipients_ui(ui);
        ui.add_space(SECTION_GAP);
        section_header(ui, "Message");
        if let Some((name, _)) = &self.enc_file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {name}"));
                clear = ui.small_button("✖").on_hover_text("Remove file").clicked();
            });
            if clear {
                self.enc_file = None;
            }
        } else {
            let edit = ui.add(
                egui::TextEdit::multiline(&mut self.enc_message)
                    .hint_text("Write your message here.")
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if edit.changed() {
                self.enc_output = None;
            }
        }
        if ui.button("📂 Encrypt a file instead…").clicked() {
            self.pick_file_to_encrypt();
        }

        ui.add_space(SECTION_GAP);
        let has_message = self.enc_file.is_some() || !self.enc_message.trim().is_empty();
        let passphrase_missing = self
            .signing_cert()
            .is_some_and(|c| encrypt::signing_needs_passphrase(&c))
            && self.enc_sign_passphrase.is_empty();
        let ready = !self.enc_recipients.is_empty() && has_message && !passphrase_missing;
        let button = egui::Button::new(RichText::new("🔒  Encrypt").size(16.0));
        if ui.add_enabled(ready, button).clicked() {
            self.run_encrypt();
        }

        self.encrypt_result_ui(ui);
    }

    /// Which of the user's keys the message is also encrypted to.
    fn sender_key_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "From");
        if self.store.my_keys.is_empty() {
            ui.label(
                RichText::new(
                    "You have no saved keys yet. Create one in New key, or import one in My keys.",
                )
                .weak(),
            );
            return;
        }
        let selected = self
            .enc_from
            .as_ref()
            .and_then(|f| self.store.name_for(f))
            .unwrap_or("Nobody (not even me)")
            .to_string();
        egui::ComboBox::from_id_salt("enc-from")
            .selected_text(selected)
            .width(260.0)
            .show_ui(ui, |ui| {
                for entry in &self.store.my_keys {
                    let fpr = Some(entry.cert.fingerprint());
                    ui.selectable_value(&mut self.enc_from, fpr, &entry.name);
                }
                ui.selectable_value(&mut self.enc_from, None, "Nobody (not even me)");
            });
        let from = self
            .chosen_own_key()
            .map(|e| (e.name.clone(), e.cert.clone()));
        match &from {
            Some((name, cert)) => {
                ui.label(
                    RichText::new(
                        "You will be able to read this message again later with this key.",
                    )
                    .weak(),
                );
                match encrypt::check_can_sign(cert) {
                    Ok(()) => {
                        ui.checkbox(&mut self.enc_sign, format!("Sign as \"{name}\""));
                        if self.enc_sign && encrypt::signing_needs_passphrase(cert) {
                            form_grid("sign-passphrase").show(ui, |ui| {
                                ui.label("Passphrase");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.enc_sign_passphrase)
                                        .password(true),
                                );
                                ui.end_row();
                            });
                        }
                    }
                    Err(e) => warning(ui, &format!("{e:#}")),
                }
            }
            None => {
                ui.label(
                    RichText::new(
                        "Once encrypted, you will not be able to read this message yourself.",
                    )
                    .weak(),
                );
            }
        }
        notice_ui(ui, &self.enc_from_notice);
        explainer(
            ui,
            "Why choose one of my keys?",
            &[
                "Each of your keys is like a separate identity: for example one for work \
                 and one for friends.",
                "The message is also locked for the key you choose here, so you can open it \
                 again later.",
                "With \"Sign\", the message also carries your signature: the recipient can \
                 check that it really comes from you and that nobody changed it. They need \
                 your public key for that, so send it to them once.",
            ],
        );
    }

    /// The From key, if one is chosen.
    fn chosen_own_key(&self) -> Option<&store::Entry> {
        let fpr = self.enc_from.as_ref()?;
        self.store
            .my_keys
            .iter()
            .find(|e| &e.cert.fingerprint() == fpr)
    }

    /// Whether the message will be signed, and with which key.
    fn signing_cert(&self) -> Option<Cert> {
        let entry = self.chosen_own_key()?;
        (self.enc_sign && encrypt::check_can_sign(&entry.cert).is_ok()).then(|| entry.cert.clone())
    }

    /// Who the message is for: contacts, or keys used just this once.
    fn recipients_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "To");
        let mut remove = None;
        for (i, cert) in self.enc_recipients.iter().enumerate() {
            if cert_row(ui, &self.display_name(cert), cert) {
                remove = Some(i);
            }
            if encrypt::uses_old_technology(cert) {
                warning(
                    ui,
                    "This key uses old technology (SHA-1). It still works, but if you can, \
                     ask its owner for a newer key.",
                );
            }
        }
        if let Some(i) = remove {
            self.enc_recipients.remove(i);
            self.enc_output = None;
            self.enc_notice = Status::None;
        }

        let mut picked = None;
        ui.horizontal_wrapped(|ui| {
            if self.store.contacts.is_empty() {
                ui.label(RichText::new("No contacts yet.").weak());
                if ui.small_button("👤 Add contacts").clicked() {
                    self.tab = Tab::Contacts;
                }
            } else {
                egui::ComboBox::from_id_salt("enc-to")
                    .selected_text("Choose a contact…")
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        for entry in &self.store.contacts {
                            if ui.selectable_label(false, &entry.name).clicked() {
                                picked = Some(entry.cert.clone());
                            }
                        }
                    });
            }
        });
        if let Some(cert) = picked {
            self.add_recipient(cert);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Or just this once:").weak());
            if ui.small_button("📂 Open public key file…").clicked()
                && let Some(bytes) = pick_key_file("Open a public key")
            {
                self.add_recipient_from(bytes);
            }
            if ui.small_button("📋 Paste public key").clicked() {
                self.add_recipient_from(clipboard_key());
            }
        });
        notice_ui(ui, &self.enc_notice);
        explainer(
            ui,
            "Whose key do I need?",
            &[
                "To send someone a secret message you need their public key. Save it once \
                 in Contacts and pick them here from then on.",
                "Only the people chosen here (and your own key, under From) can open the \
                 message.",
            ],
        );
    }

    fn encrypt_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(output) = &self.enc_output else {
            return;
        };

        ui.separator();
        ui.heading("Encrypted message");
        ui.label("Copy this text and send it to the recipients. Only they can open it.");
        let mut copy = false;
        let mut save = false;
        ui.horizontal(|ui| {
            copy = ui.button("📋 Copy").clicked();
            save = ui.button("💾 Save…").clicked();
        });
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut output.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });

        if copy {
            let text = output.clone();
            self.status = match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
                Ok(()) => Status::Info("Encrypted message copied to clipboard.".into()),
                Err(e) => Status::Error(format!("Could not copy: {e}")),
            };
        }
        if save
            && let Some(path) = rfd::FileDialog::new()
                .set_title("Save encrypted message")
                .set_file_name("message.asc")
                .add_filter("ASCII armored text (.asc)", &["asc"])
                .add_filter("Text (.txt)", &["txt"])
                .save_file()
        {
            self.status = match std::fs::write(&path, output) {
                Ok(()) => Status::Info(format!("Saved to {}", path.display())),
                Err(e) => Status::Error(format!("Could not save: {e}")),
            };
        }
    }

    fn add_recipient(&mut self, cert: Cert) {
        if let Err(e) = encrypt::check_can_encrypt(&cert) {
            self.enc_notice = Status::Error(format!("{e:#}"));
            return;
        }
        if self
            .enc_recipients
            .iter()
            .any(|c| c.fingerprint() == cert.fingerprint())
        {
            self.enc_notice = Status::Info("This key is already in the list.".into());
            return;
        }
        self.enc_recipients.push(cert);
        self.enc_output = None;
        self.enc_notice = Status::None;
    }

    fn add_recipient_from(&mut self, bytes: anyhow::Result<Vec<u8>>) {
        match bytes.and_then(|bytes| encrypt::load_public_key(&bytes)) {
            Ok(cert) => self.add_recipient(cert),
            Err(e) => self.enc_notice = Status::Error(format!("{e:#}")),
        }
    }

    fn pick_file_to_encrypt(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose a file to encrypt")
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path) {
            Ok(bytes) => {
                self.enc_file = Some((file_name(&path), bytes));
                self.enc_output = None;
                self.status = Status::None;
            }
            Err(e) => self.status = Status::Error(format!("Could not open the file: {e}")),
        }
    }

    /// The chosen recipients plus the From key.
    fn all_recipients(&self) -> Vec<Cert> {
        let mut all = self.enc_recipients.clone();
        let from = self.enc_from.as_ref().and_then(|f| {
            self.store
                .my_keys
                .iter()
                .find(|e| &e.cert.fingerprint() == f)
        });
        if let Some(entry) = from
            && !all
                .iter()
                .any(|c| c.fingerprint() == entry.cert.fingerprint())
        {
            all.push(entry.cert.clone().strip_secret_key_material());
        }
        all
    }

    fn run_encrypt(&mut self) {
        let recipients = self.all_recipients();
        self.enc_from_notice = Status::None;
        let signer = match self.signing_cert() {
            Some(cert) => match encrypt::signer(&cert, Some(&self.enc_sign_passphrase)) {
                Ok(signer) => Some(signer),
                Err(e) => {
                    self.enc_from_notice = Status::Error(format!("{e:#}"));
                    return;
                }
            },
            None => None,
        };
        let signed_as = signer
            .as_ref()
            .and_then(|_| self.chosen_own_key())
            .map(|e| format!(" and signed as \"{}\"", e.name))
            .unwrap_or_default();
        match &self.enc_file {
            // Files are saved as binary .gpg right away, like GnuPG does.
            Some((name, bytes)) => {
                let encrypted = match encrypt::encrypt(&recipients, bytes, false, signer) {
                    Ok(e) => e,
                    Err(e) => {
                        self.status = Status::Error(format!("{e:#}"));
                        return;
                    }
                };
                let Some(path) = rfd::FileDialog::new()
                    .set_title("Save encrypted file")
                    .set_file_name(format!("{name}.gpg"))
                    .add_filter("Encrypted file (.gpg)", &["gpg"])
                    .save_file()
                else {
                    return;
                };
                self.status = match std::fs::write(&path, encrypted) {
                    Ok(()) => Status::Info(format!(
                        "File encrypted{signed_as}, saved to {}",
                        path.display()
                    )),
                    Err(e) => Status::Error(format!("Could not save: {e}")),
                };
            }
            None => {
                match encrypt::encrypt(&recipients, self.enc_message.as_bytes(), true, signer)
                    .and_then(|bytes| Ok(String::from_utf8(bytes)?))
                {
                    Ok(text) => {
                        self.enc_output = Some(text);
                        self.status = Status::Info(format!("Message encrypted{signed_as}."));
                    }
                    Err(e) => self.status = Status::Error(format!("{e:#}")),
                }
            }
        }
    }
}
