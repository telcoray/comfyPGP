//! Graphical user interface (egui).

use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};

use sequoia_openpgp::Cert;

use crate::keygen::{self, Algorithm, Encoding, GeneratedKey, KeyRequest, Part};
use crate::{decrypt, encrypt};

const YEAR: u64 = 365 * 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expiry {
    Never,
    Years(u64),
}

impl Expiry {
    const CHOICES: [Expiry; 5] = [
        Expiry::Never,
        Expiry::Years(1),
        Expiry::Years(2),
        Expiry::Years(3),
        Expiry::Years(5),
    ];

    fn label(self) -> String {
        match self {
            Expiry::Never => "Never".into(),
            Expiry::Years(1) => "1 year".into(),
            Expiry::Years(n) => format!("{n} years"),
        }
    }

    fn duration(self) -> Option<Duration> {
        match self {
            Expiry::Never => None,
            Expiry::Years(n) => Some(Duration::from_secs(n * YEAR)),
        }
    }
}

enum Status {
    None,
    Info(String),
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Generate,
    Encrypt,
    Decrypt,
}

pub struct ComfyApp {
    tab: Tab,

    name: String,
    email: String,
    algorithm: Algorithm,
    expiry: Expiry,
    use_passphrase: bool,
    passphrase: String,
    passphrase_repeat: String,

    pending: Option<Receiver<anyhow::Result<GeneratedKey>>>,
    key: Option<GeneratedKey>,
    public_armored: String,

    enc_recipients: Vec<Cert>,
    enc_message: String,
    /// A file to encrypt instead of the text: (file name, contents).
    enc_file: Option<(String, Vec<u8>)>,
    enc_output: Option<String>,
    /// Feedback on adding recipients, shown right under the buttons.
    enc_notice: Status,

    dec_key: Option<Cert>,
    dec_message: String,
    /// A binary message opened from a file: (file name, contents).
    dec_file: Option<(String, Vec<u8>)>,
    dec_passphrase: String,
    dec_output: Option<Vec<u8>>,

    status: Status,
}

impl Default for ComfyApp {
    fn default() -> Self {
        Self {
            tab: Tab::Generate,
            name: String::new(),
            email: String::new(),
            algorithm: Algorithm::Cv25519,
            expiry: Expiry::Years(2),
            use_passphrase: true,
            passphrase: String::new(),
            passphrase_repeat: String::new(),
            pending: None,
            key: None,
            public_armored: String::new(),
            enc_recipients: Vec::new(),
            enc_message: String::new(),
            enc_file: None,
            enc_output: None,
            enc_notice: Status::None,
            dec_key: None,
            dec_message: String::new(),
            dec_file: None,
            dec_passphrase: String::new(),
            dec_output: None,
            status: Status::None,
        }
    }
}

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

    fn poll_generation(&mut self) {
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
                self.status = Status::Info(
                    "Key created! Remember to save the secret key and the revocation certificate."
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

    fn form_ui(&mut self, ui: &mut egui::Ui) {
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

    fn result_ui(&mut self, ui: &mut egui::Ui) {
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

    fn encrypt_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Recipients");
        if self.enc_recipients.is_empty() {
            ui.label(RichText::new("Add the public key of the person you are writing to.").weak());
        }
        let mut remove = None;
        for (i, cert) in self.enc_recipients.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "✔ {}  ·  {}",
                    user_id_of(cert),
                    keygen::pretty_fingerprint(cert)
                ));
                if ui.small_button("✕").on_hover_text("Remove").clicked() {
                    remove = Some(i);
                }
            });
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
        let mine = self.key.as_ref().map(|k| k.cert.clone());
        ui.horizontal_wrapped(|ui| {
            if ui.button("📂 Open public key file…").clicked() {
                self.open_recipient_key();
            }
            if ui.button("📋 Paste public key").clicked() {
                self.paste_recipient_key();
            }
            if let Some(cert) = mine
                && ui.button("Add the key I just created").clicked()
            {
                self.add_recipient(cert);
            }
        });
        match &self.enc_notice {
            Status::None => {}
            Status::Info(msg) => {
                ui.label(RichText::new(msg).weak());
            }
            Status::Error(msg) => {
                ui.colored_label(ERROR_COLOR, msg);
            }
        }
        explainer(
            ui,
            "Whose key do I need?",
            &[
                "To send someone a secret message you need their public key. They can \
                 send it to you, or publish it on their website or a key server.",
                "Once encrypted, only the recipients can open the message: not even you. \
                 Add your own public key too if you want to read it again later.",
            ],
        );

        ui.add_space(SECTION_GAP);
        section_header(ui, "Message");
        if let Some((name, _)) = &self.enc_file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {name}"));
                clear = ui.small_button("✕").on_hover_text("Remove file").clicked();
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
        let ready = !self.enc_recipients.is_empty() && has_message;
        let button = egui::Button::new(RichText::new("🔒  Encrypt").size(16.0));
        if ui.add_enabled(ready, button).clicked() {
            self.run_encrypt();
        }

        self.encrypt_result_ui(ui);
    }

    fn encrypt_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(output) = &self.enc_output else {
            return;
        };

        ui.separator();
        ui.heading("Encrypted message");
        ui.label("Send this text to the recipients. Only they can open it.");
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

    fn open_recipient_key(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Open a public key")
            .add_filter(
                "PGP key (.asc, .txt, .gpg, .key)",
                &["asc", "txt", "gpg", "key"],
            )
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| encrypt::load_public_key(&bytes))
        {
            Ok(cert) => self.add_recipient(cert),
            Err(e) => self.enc_notice = Status::Error(format!("{e:#}")),
        }
    }

    fn paste_recipient_key(&mut self) {
        let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
            Ok(text) => text,
            Err(_) => {
                self.enc_notice =
                    Status::Error("The clipboard is empty. Copy a public key first.".into());
                return;
            }
        };
        match encrypt::load_public_key(text.trim().as_bytes()) {
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

    fn run_encrypt(&mut self) {
        match &self.enc_file {
            // Files are saved as binary .gpg right away, like GnuPG does.
            Some((name, bytes)) => {
                let encrypted = match encrypt::encrypt(&self.enc_recipients, bytes, false) {
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
                    Ok(()) => Status::Info(format!("Encrypted file saved to {}", path.display())),
                    Err(e) => Status::Error(format!("Could not save: {e}")),
                };
            }
            None => {
                match encrypt::encrypt(&self.enc_recipients, self.enc_message.as_bytes(), true)
                    .and_then(|bytes| Ok(String::from_utf8(bytes)?))
                {
                    Ok(text) => {
                        self.enc_output = Some(text);
                        self.status = Status::Info("Message encrypted.".into());
                    }
                    Err(e) => self.status = Status::Error(format!("{e:#}")),
                }
            }
        }
    }

    fn decrypt_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Your secret key");
        match &self.dec_key {
            Some(cert) => {
                ui.label(format!(
                    "✔ {}  ·  {}",
                    user_id_of(cert),
                    keygen::pretty_fingerprint(cert)
                ));
            }
            None => {
                ui.label(
                    RichText::new("Choose the secret key you saved when you created your key.")
                        .weak(),
                );
            }
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("📂 Open secret key file…").clicked() {
                self.open_secret_key();
            }
            if let Some(key) = &self.key
                && ui.button("Use the key I just created").clicked()
            {
                self.dec_key = Some(key.cert.clone());
                self.dec_output = None;
                self.status = Status::None;
            }
        });
        explainer(
            ui,
            "Which key do I need?",
            &[
                "People lock messages for you with your public key. Only the matching \
                 secret key can open them: the file you saved with \"Save secret key\".",
                "A public key file will not work here, and neither will someone else's key.",
            ],
        );

        ui.add_space(SECTION_GAP);
        section_header(ui, "Encrypted message");
        if let Some((name, _)) = &self.dec_file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {name}"));
                clear = ui.small_button("✕").on_hover_text("Remove file").clicked();
            });
            if clear {
                self.dec_file = None;
                self.dec_output = None;
            }
        } else {
            ui.add(
                egui::TextEdit::multiline(&mut self.dec_message)
                    .hint_text("Paste the message here. It starts with -----BEGIN PGP MESSAGE-----")
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
        }
        if ui.button("📂 Open encrypted file…").clicked() {
            self.open_encrypted_file();
        }

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

    fn decrypt_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(output) = &self.dec_output else {
            return;
        };

        ui.separator();
        ui.heading("Decrypted message");
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
                self.dec_key = Some(cert);
                self.dec_passphrase.clear();
                self.dec_output = None;
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
    }

    fn run_decrypt(&mut self, needs_passphrase: bool) {
        let Some(cert) = &self.dec_key else { return };
        let message = match &self.dec_file {
            Some((_, bytes)) => bytes.as_slice(),
            None => self.dec_message.trim().as_bytes(),
        };
        let passphrase = needs_passphrase.then_some(self.dec_passphrase.as_str());
        match decrypt::decrypt(cert, passphrase, message) {
            Ok(plaintext) => {
                self.dec_output = Some(plaintext);
                self.dec_passphrase.clear();
                self.status = Status::Info("Message decrypted.".into());
            }
            Err(e) => {
                self.dec_output = None;
                self.status = Status::Error(format!("{e:#}"));
            }
        }
    }

    fn save_decrypted(&mut self) {
        let Some(output) = &self.dec_output else {
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

impl eframe::App for ComfyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_generation();

        egui::Panel::bottom("status").show(ui, |ui| match &self.status {
            Status::None => {
                ui.label("");
            }
            Status::Info(msg) => {
                ui.label(msg);
            }
            Status::Error(msg) => {
                ui.colored_label(ERROR_COLOR, msg);
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("comfyPGP");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let generate = RichText::new("🔑 Generate key").size(15.0);
                    let encrypt = RichText::new("🔒 Encrypt").size(15.0);
                    let decrypt = RichText::new("🔓 Decrypt").size(15.0);
                    ui.selectable_value(&mut self.tab, Tab::Generate, generate);
                    ui.selectable_value(&mut self.tab, Tab::Encrypt, encrypt);
                    ui.selectable_value(&mut self.tab, Tab::Decrypt, decrypt);
                });
                ui.separator();
                ui.add_space(6.0);
                match self.tab {
                    Tab::Generate => {
                        self.form_ui(ui);
                        self.result_ui(ui);
                    }
                    Tab::Encrypt => self.encrypt_ui(ui),
                    Tab::Decrypt => self.decrypt_ui(ui),
                }
            });
        });
    }
}

const SECTION_GAP: f32 = 16.0;
const ERROR_COLOR: Color32 = Color32::from_rgb(220, 70, 70);

fn user_id_of(cert: &Cert) -> String {
    cert.userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .unwrap_or_else(|| "(no User ID)".into())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add_space(4.0);
}

/// Collapsed "Why…?" section with a few short paragraphs.
fn explainer(ui: &mut egui::Ui, question: &str, paragraphs: &[&str]) {
    egui::CollapsingHeader::new(question)
        .id_salt(question)
        .show(ui, |ui| {
            for (i, p) in paragraphs.iter().enumerate() {
                if i > 0 {
                    ui.add_space(4.0);
                }
                ui.label(*p);
            }
        });
}

fn form_grid(id: &str) -> egui::Grid {
    egui::Grid::new(id)
        .num_columns(2)
        .min_col_width(130.0)
        .spacing([12.0, 8.0])
}

/// A clickable card that behaves like a radio button.
/// Returns `true` when clicked.
fn choice_card(
    ui: &mut egui::Ui,
    selected: bool,
    title: &str,
    badge: Option<&str>,
    description: &str,
    technical: &str,
) -> bool {
    let visuals = ui.visuals();
    let stroke = if selected {
        egui::Stroke::new(2.0, visuals.selection.stroke.color)
    } else {
        egui::Stroke::new(1.0, visuals.widgets.noninteractive.bg_stroke.color)
    };

    let mut radio_clicked = false;
    let response = egui::Frame::new()
        .stroke(stroke)
        .corner_radius(6.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Selectable text would swallow clicks meant for the card.
            ui.style_mut().interaction.selectable_labels = false;
            ui.horizontal(|ui| {
                radio_clicked = ui.radio(selected, "").clicked();
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(title).strong().size(15.0));
                        if let Some(badge) = badge {
                            ui.label(
                                RichText::new(badge)
                                    .small()
                                    .color(Color32::WHITE)
                                    .background_color(Color32::from_rgb(60, 140, 90)),
                            );
                        }
                    });
                    ui.label(description);
                    ui.label(RichText::new(technical).small().weak());
                });
            });
        })
        .response
        .interact(egui::Sense::click());

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response.clicked() || radio_clicked
}

fn warning(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(format!("⚠ {text}")).color(Color32::from_rgb(210, 150, 40)));
}

fn encoding_for(path: &Path) -> Encoding {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("gpg") => Encoding::Binary,
        _ => Encoding::Armored,
    }
}
