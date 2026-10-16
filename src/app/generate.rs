//! The Generate key tab.

use super::*;

impl ComfyApp {
    fn form_error(&self) -> Option<&'static str> {
        if self.use_passphrase {
            if self.passphrase.is_empty() {
                return Some("Enter a passphrase (or turn it off).");
            }
            if self.passphrase != self.passphrase_repeat {
                return Some("The passphrases do not match.");
            }
        }
        None
    }

    fn start_generation(&mut self, ctx: &egui::Context) {
        let req = KeyRequest {
            name: self.name.clone(),
            email: self.email.clone(),
            algorithm: self.algorithm,
            validity: self.expiry.duration(),
            passphrase: self.use_passphrase.then(|| self.passphrase.clone()),
        };
        self.passphrase.clear();
        self.passphrase_repeat.clear();

        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(keygen::generate(&req));
            ctx.request_repaint();
        });
        self.pending = Some(rx);
        self.status = Status::Info("Generating key…".into());
    }

    pub(super) fn poll_generation(&mut self) {
        let Some(rx) = &self.pending else { return };
        let Ok(result) = rx.try_recv() else { return };
        self.pending = None;
        match result.and_then(|key| {
            let armored = keygen::export(&key, Part::Public, Encoding::Armored)?;
            Ok((key, String::from_utf8(armored)?))
        }) {
            Ok((key, armored)) => {
                self.key = Some(key);
                self.public_armored = armored;
                self.gen_save_name = match self.name.trim() {
                    "" => "My key".into(),
                    name => name.into(),
                };
                self.gen_saved_as = None;
                self.status = Status::Info(
                    "Key created! Save it to My keys, and keep the revocation certificate safe."
                        .into(),
                );
            }
            Err(e) => self.status = Status::Error(format!("Key generation failed: {e:#}")),
        }
    }

    fn save(&mut self, part: Part) {
        let Some(key) = &self.key else { return };
        let short = key.cert.fingerprint().to_hex();
        let short = &short[short.len() - 8..];
        let (title, suffix) = match part {
            Part::Public => ("Save public key", "public"),
            Part::Secret => ("Save SECRET key", "secret"),
            Part::Revocation => ("Save revocation certificate", "revocation"),
        };

        let Some(mut path) = rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(format!("comfyPGP-{short}-{suffix}.asc"))
            .add_filter("ASCII armored text (.asc)", &["asc"])
            .add_filter("Text (.txt)", &["txt"])
            .add_filter("Binary (.gpg)", &["gpg"])
            .save_file()
        else {
            return;
        };

        if path.extension().is_none() {
            path.set_extension("asc");
        }
        let encoding = encoding_for(&path);

        let result = keygen::export(key, part, encoding)
            .and_then(|bytes| std::fs::write(&path, bytes).map_err(Into::into));
        self.status = match result {
            Ok(()) => Status::Info(format!("Saved to {}", path.display())),
            Err(e) => Status::Error(format!("Could not save: {e:#}")),
        };
    }

    fn copy_public(&mut self) {
        self.status = match arboard::Clipboard::new()
            .and_then(|mut c| c.set_text(self.public_armored.clone()))
        {
            Ok(()) => Status::Info("Public key copied to clipboard.".into()),
            Err(e) => Status::Error(format!("Could not copy: {e}")),
        };
    }

    pub(super) fn form_ui(&mut self, ui: &mut egui::Ui) {
        let busy = self.pending.is_some();
        ui.add_enabled_ui(!busy, |ui| {
            self.identity_ui(ui);
            ui.add_space(SECTION_GAP);
            self.key_type_ui(ui);
            ui.add_space(SECTION_GAP);
            self.expiry_ui(ui);
            ui.add_space(SECTION_GAP);
            self.passphrase_ui(ui);
            ui.add_space(SECTION_GAP);

            let error = self.form_error();
            ui.horizontal(|ui| {
                let button = egui::Button::new(RichText::new("🔑  Generate key").size(16.0));
                if ui.add_enabled(error.is_none(), button).clicked() {
                    self.start_generation(ui.ctx());
                }
                if busy {
                    ui.spinner();
                }
            });
            if let Some(error) = error {
                ui.label(RichText::new(error).weak());
            }
        });
    }

    // Every section is written for people who have never used PGP:
    // the controls, any warning right below them, and an optional
    // "Why…?" for the curious.

    fn identity_ui(&mut self, ui: &mut egui::Ui) {
        form_grid("identity").show(ui, |ui| {
            ui.label("Name or nickname");
            ui.add(egui::TextEdit::singleline(&mut self.name).hint_text("optional (recommended)"));
            ui.end_row();

            ui.label("Email");
            ui.add(egui::TextEdit::singleline(&mut self.email).hint_text("optional"));
            ui.end_row();
        });
        explainer(
            ui,
            "Why are these optional?",
            &[
                "Your name and email are not part of the security. They are just a label \
                 written on your public key, so people can tell whose key it is.",
                "Using PGP for email? Enter your name and email address. Mail apps use the \
                 address to find your key automatically when someone writes to you.",
                "Using PGP for something more private? Enter only a nickname and leave the \
                 email empty. Anyone who gets your public key can read this label, so it \
                 should not lead back to you.",
                "Some apps, like Kleopatra, need at least a name or nickname to accept the \
                 key. That is why it is recommended.",
            ],
        );
    }

    fn expiry_ui(&mut self, ui: &mut egui::Ui) {
        form_grid("expiry").show(ui, |ui| {
            ui.label("Expires");
            egui::ComboBox::from_id_salt("expiry")
                .selected_text(self.expiry.label())
                .show_ui(ui, |ui| {
                    for e in Expiry::CHOICES {
                        ui.selectable_value(&mut self.expiry, e, e.label());
                    }
                });
            ui.end_row();
        });
        if self.expiry == Expiry::Never {
            warning(
                ui,
                "The key never expires by itself. Keep the revocation certificate safe: \
                 it is your only way to retire the key.",
            );
        }
        explainer(
            ui,
            "What happens when it expires?",
            &[
                "Nothing is lost. People simply stop using the key for new messages, and \
                 you can still open the ones you already received.",
                "Before or after that day, you can push the date forward with any PGP app \
                 (for example Kleopatra) and keep the very same key.",
                "The date protects you if you lose the key or forget the passphrase: it \
                 retires itself instead of staying around forever. That is why a date is \
                 safer than \"Never\".",
            ],
        );
    }

    fn passphrase_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Lock your secret key");
        ui.checkbox(
            &mut self.use_passphrase,
            "Protect the secret key with a passphrase",
        );
        if self.use_passphrase {
            form_grid("passphrase").show(ui, |ui| {
                ui.label("Passphrase");
                ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                ui.end_row();

                ui.label("Repeat passphrase");
                ui.add(egui::TextEdit::singleline(&mut self.passphrase_repeat).password(true));
                ui.end_row();
            });
        } else {
            warning(
                ui,
                "Without a passphrase, anyone who gets a copy of your secret key file can \
                 read your messages and sign as you.",
            );
        }
        explainer(
            ui,
            "Why does this matter?",
            &[
                "Your secret key is just a file. If someone copies it (a stolen laptop, a \
                 cloud backup, a virus), they could read your messages and sign as you. \
                 The passphrase scrambles the file so it is useless without it.",
                "You will type it whenever you decrypt or sign something.",
                "There is no \"forgot passphrase\": if you lose it, the key cannot be used \
                 anymore. Write it down and keep it somewhere safe.",
                "Turn it off only if the file will live somewhere already protected, like \
                 an encrypted drive.",
            ],
        );
    }

    /// Key type picker: plain names first, the technical name only as a footnote.
    fn key_type_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Key type");
        ui.label(RichText::new("Both are equally secure. Not sure? Keep Modern.").weak());
        ui.add_space(4.0);

        let cards = [
            (
                Algorithm::Cv25519,
                "Modern",
                Some("Recommended"),
                "Small, fast and the default in today's PGP apps \
                 (GnuPG, Kleopatra, Thunderbird, Proton Mail).",
                "Ed25519 / Curve25519",
            ),
            (
                Algorithm::Rsa4096,
                "Classic",
                None,
                "Only if someone asks you for an RSA key, or you need to talk to \
                 very old PGP software. Bigger, and takes a few seconds to create.",
                "RSA 4096",
            ),
        ];
        for (algorithm, title, badge, description, technical) in cards {
            if choice_card(
                ui,
                self.algorithm == algorithm,
                title,
                badge,
                description,
                technical,
            ) {
                self.algorithm = algorithm;
            }
            ui.add_space(4.0);
        }

        explainer(
            ui,
            "Why are there two?",
            &[
                "PGP has been around since 1991. RSA is the original kind of key and \
                 every PGP program understands it. Modern keys use newer math \
                 (elliptic curves): they give the same protection with much smaller \
                 keys. GnuPG has supported them since 2014 and makes them by default \
                 since 2021.",
                "The choice only affects size, speed and which programs can read your \
                 key, not how safe your messages are.",
            ],
        );
    }

    pub(super) fn result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(key) = &self.key else { return };

        ui.separator();
        ui.heading("Your key");
        ui.horizontal(|ui| {
            ui.label("Fingerprint:");
            ui.label(
                RichText::new(keygen::pretty_fingerprint(&key.cert))
                    .monospace()
                    .strong(),
            );
        });
        ui.label(format!("User ID: {}", user_id_of(&key.cert)));

        ui.add_space(8.0);
        match &self.gen_saved_as {
            Some(name) => {
                ui.colored_label(GOOD_COLOR, format!("✔ Saved in My keys as \"{name}\""));
            }
            None => {
                let mut save = false;
                ui.horizontal(|ui| {
                    ui.label("Name in My keys");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.gen_save_name)
                            .hint_text("e.g. work, friends"),
                    );
                    save = ui.button("🔑 Save to My keys").clicked();
                });
                ui.label(
                    RichText::new("Pick a name you will recognize, like \"work\" or \"friends\".")
                        .weak(),
                );
                if save {
                    self.save_generated_to_book();
                }
            }
        }

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button("📋 Copy public key").clicked() {
                self.copy_public();
            }
            if ui.button("💾 Save public key…").clicked() {
                self.save(Part::Public);
            }
            if ui.button("🔒 Save secret key…").clicked() {
                self.save(Part::Secret);
            }
            if ui.button("⛔ Save revocation certificate…").clicked() {
                self.save(Part::Revocation);
            }
        });

        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.public_armored.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
    }

    fn save_generated_to_book(&mut self) {
        let Some(key) = &self.key else { return };
        let cert = key.cert.clone();
        let name = self.gen_save_name.clone();
        match self.store.add_my_key(&name, cert) {
            Ok(()) => {
                self.gen_saved_as = Some(name.trim().to_string());
                self.after_my_keys_changed();
                self.persist();
            }
            Err(e) => self.status = Status::Error(format!("{e:#}")),
        }
    }
}
