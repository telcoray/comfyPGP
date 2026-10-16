//! The Sign & Verify tab: signatures without encryption.

use std::path::PathBuf;

use super::*;
use crate::sign;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    #[default]
    Sign,
    Verify,
}

/// A file picked by the user: name, where it is, contents.
struct PickedFile {
    name: String,
    path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub(super) struct SignState {
    mode: Mode,

    key: Option<Fingerprint>,
    passphrase: String,
    text: String,
    file: Option<PickedFile>,
    output: Option<String>,
    notice: Status,

    verify_text: String,
    verify_file: Option<PickedFile>,
    verify_sig: Option<PickedFile>,
    signers: Vec<Cert>,
    signer_notice: Status,
    verify_notice: Status,
    /// The outcome, and for text the part the signature covers.
    result: Option<(SignatureCheck, Option<String>)>,
}

impl ComfyApp {
    pub(super) fn sign_tab_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let modes = [(Mode::Sign, "🖊 Sign"), (Mode::Verify, "🔍 Verify")];
            for (mode, label) in modes {
                ui.selectable_value(&mut self.sign.mode, mode, RichText::new(label).size(14.0));
            }
        });
        ui.add_space(8.0);
        match self.sign.mode {
            Mode::Sign => self.sign_ui(ui),
            Mode::Verify => self.verify_ui(ui),
        }
    }

    // ----- Sign -----

    fn sign_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Sign as");
        if self.store.my_keys.is_empty() {
            ui.label(
                RichText::new(
                    "You have no saved keys yet. Create one in New key, or import one in My keys.",
                )
                .weak(),
            );
            return;
        }
        let exists = |f: &Fingerprint| {
            self.store
                .my_keys
                .iter()
                .any(|e| &e.cert.fingerprint() == f)
        };
        if !self.sign.key.as_ref().is_some_and(exists) {
            self.sign.key = self
                .enc_from
                .clone()
                .filter(exists)
                .or_else(|| self.store.my_keys.first().map(|e| e.cert.fingerprint()));
        }
        let selected = self
            .sign
            .key
            .as_ref()
            .and_then(|f| self.store.name_for(f))
            .unwrap_or_default()
            .to_string();
        egui::ComboBox::from_id_salt("sign-key")
            .selected_text(selected)
            .width(260.0)
            .show_ui(ui, |ui| {
                for entry in &self.store.my_keys {
                    let fpr = Some(entry.cert.fingerprint());
                    ui.selectable_value(&mut self.sign.key, fpr, &entry.name);
                }
            });
        let cert = self.signing_key_for_tab();
        let mut can_sign = false;
        if let Some(cert) = &cert {
            match encrypt::check_can_sign(cert) {
                Ok(()) => {
                    can_sign = true;
                    if encrypt::signing_needs_passphrase(cert) {
                        form_grid("sign-tab-passphrase").show(ui, |ui| {
                            ui.label("Passphrase");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.sign.passphrase)
                                    .password(true),
                            );
                            ui.end_row();
                        });
                    }
                }
                Err(e) => warning(ui, &format!("{e:#}")),
            }
        }

        ui.add_space(SECTION_GAP);
        section_header(ui, "What to sign");
        if let Some(file) = &self.sign.file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {}", file.name));
                clear = ui.small_button("✖").on_hover_text("Remove file").clicked();
            });
            if clear {
                self.sign.file = None;
            }
        } else {
            let edit = ui.add(
                egui::TextEdit::multiline(&mut self.sign.text)
                    .hint_text("Write or paste the text to sign.")
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if edit.changed() {
                self.sign.output = None;
            }
        }
        if ui.button("📂 Sign a file instead…").clicked()
            && let Some(file) = pick_any_file("Choose a file to sign")
        {
            match file {
                Ok(file) => {
                    self.sign.file = Some(file);
                    self.sign.output = None;
                    self.sign.notice = Status::None;
                }
                Err(e) => self.sign.notice = Status::Error(e),
            }
        }

        ui.add_space(SECTION_GAP);
        let has_content = self.sign.file.is_some() || !self.sign.text.trim().is_empty();
        let passphrase_missing = cert.as_ref().is_some_and(encrypt::signing_needs_passphrase)
            && self.sign.passphrase.is_empty();
        let ready = can_sign && has_content && !passphrase_missing;
        let button = egui::Button::new(RichText::new("🖊  Sign").size(16.0));
        if ui.add_enabled(ready, button).clicked()
            && let Some(cert) = cert
        {
            self.run_sign(&cert);
        }
        notice_ui(ui, &self.sign.notice);
        explainer(
            ui,
            "When should I sign without encrypting?",
            &[
                "When the content is not secret, but people must be sure it comes from you \
                 and was not changed: a public announcement, a document you send to many \
                 people, or a program you publish.",
                "Signing hides nothing: anyone can read a signed text. With your public key, \
                 they can also check that you wrote it.",
                "For a file, comfyPGP makes a separate signature file. Share it together \
                 with the file.",
            ],
        );

        self.sign_result_ui(ui);
    }

    fn signing_key_for_tab(&self) -> Option<Cert> {
        let fpr = self.sign.key.as_ref()?;
        self.store
            .my_keys
            .iter()
            .find(|e| &e.cert.fingerprint() == fpr)
            .map(|e| e.cert.clone())
    }

    fn run_sign(&mut self, cert: &Cert) {
        self.sign.notice = Status::None;
        let signer = match encrypt::signer(cert, Some(&self.sign.passphrase)) {
            Ok(signer) => signer,
            Err(e) => {
                self.sign.notice = Status::Error(format!("{e:#}"));
                return;
            }
        };
        let name = self.display_name(cert);
        match &self.sign.file {
            Some(file) => {
                let Some(path) = rfd::FileDialog::new()
                    .set_title("Save the signature")
                    .set_directory(file.path.parent().unwrap_or(Path::new(".")))
                    .set_file_name(format!("{}.asc", file.name))
                    .add_filter("Signature as text (.asc)", &["asc"])
                    .add_filter("Signature, binary (.sig)", &["sig"])
                    .save_file()
                else {
                    return;
                };
                let armor = !path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("sig"));
                self.sign.notice = match sign::sign_file(signer, &file.bytes, armor)
                    .and_then(|sig| std::fs::write(&path, sig).map_err(Into::into))
                {
                    Ok(()) => Status::Info(format!(
                        "Signed as \"{name}\". Signature saved to {}. Share it together with the file.",
                        path.display()
                    )),
                    Err(e) => Status::Error(format!("{e:#}")),
                };
            }
            None => match sign::sign_text(signer, &self.sign.text) {
                Ok(signed) => {
                    self.sign.output = Some(signed);
                    self.status = Status::Info(format!("Text signed as \"{name}\"."));
                }
                Err(e) => self.sign.notice = Status::Error(format!("{e:#}")),
            },
        }
    }

    fn sign_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some(output) = &self.sign.output else {
            return;
        };
        ui.separator();
        ui.heading("Signed text");
        ui.label("Anyone can read it. With your public key, they can check it comes from you.");
        let mut copy = false;
        let mut save = false;
        ui.horizontal(|ui| {
            copy = ui.button("📋 Copy").clicked();
            save = ui.button("💾 Save…").clicked();
        });
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .id_salt("signed-text")
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
                Ok(()) => Status::Info("Signed text copied to clipboard.".into()),
                Err(e) => Status::Error(format!("Could not copy: {e}")),
            };
        }
        if save {
            let bytes = output.clone().into_bytes();
            self.save_text("signed.asc", "Save signed text", &bytes);
        }
    }

    // ----- Verify -----

    fn verify_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Signed text or file");
        if let Some(file) = &self.sign.verify_file {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(format!("📄 {}", file.name));
                clear = ui.small_button("✖").on_hover_text("Remove file").clicked();
            });
            match &self.sign.verify_sig {
                Some(sig) => {
                    ui.label(RichText::new(format!("Signature: {}", sig.name)).weak());
                }
                None => {
                    ui.label(RichText::new("Now choose its signature file.").weak());
                }
            }
            let mut pick_sig = false;
            ui.horizontal(|ui| {
                let label = if self.sign.verify_sig.is_some() {
                    "📂 Choose another signature file…"
                } else {
                    "📂 Choose the signature file…"
                };
                pick_sig = ui.small_button(label).clicked();
            });
            if clear {
                self.sign.verify_file = None;
                self.sign.verify_sig = None;
                self.sign.result = None;
            }
            if pick_sig && let Some(sig) = pick_any_file("Choose the signature file") {
                match sig {
                    Ok(sig) => {
                        self.sign.verify_sig = Some(sig);
                        self.sign.result = None;
                    }
                    Err(e) => self.sign.verify_notice = Status::Error(e),
                }
            }
        } else {
            let edit = ui.add(
                egui::TextEdit::multiline(&mut self.sign.verify_text)
                    .hint_text(
                        "Paste a signed text. It starts with -----BEGIN PGP SIGNED MESSAGE-----",
                    )
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if edit.changed() {
                self.sign.result = None;
            }
            if ui.button("📂 Check a file instead…").clicked()
                && let Some(file) = pick_any_file("Choose the signed file")
            {
                match file {
                    Ok(file) => {
                        self.sign.verify_sig = find_signature_next_to(&file.path);
                        self.sign.verify_file = Some(file);
                        self.sign.result = None;
                        self.sign.verify_notice = Status::None;
                    }
                    Err(e) => self.sign.verify_notice = Status::Error(e),
                }
            }
        }

        ui.add_space(SECTION_GAP);
        self.signer_ui(ui);

        ui.add_space(SECTION_GAP);
        let ready = match &self.sign.verify_file {
            Some(_) => self.sign.verify_sig.is_some(),
            None => !self.sign.verify_text.trim().is_empty(),
        };
        let button = egui::Button::new(RichText::new("🔍  Check signature").size(16.0));
        if ui.add_enabled(ready, button).clicked() {
            self.run_verify();
        }
        notice_ui(ui, &self.sign.verify_notice);

        self.verify_result_ui(ui);
    }

    fn signer_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Signer (optional)");
        if self.sign.signers.is_empty() {
            ui.label(
                RichText::new(
                    "Signatures from your contacts are checked automatically. Add a key here \
                     only for someone who is not in your contacts.",
                )
                .weak(),
            );
        }
        let mut remove = None;
        for (i, cert) in self.sign.signers.iter().enumerate() {
            if cert_row(ui, &self.display_name(cert), cert) {
                remove = Some(i);
            }
        }
        if let Some(i) = remove {
            self.sign.signers.remove(i);
            self.sign.result = None;
        }
        ui.horizontal_wrapped(|ui| {
            if ui.small_button("📂 Open public key file…").clicked()
                && let Some(bytes) = pick_key_file("Open the signer's public key")
            {
                self.add_signer_from(bytes);
            }
            if ui.small_button("📋 Paste public key").clicked() {
                self.add_signer_from(clipboard_key());
            }
        });
        notice_ui(ui, &self.sign.signer_notice);
    }

    fn add_signer_from(&mut self, bytes: anyhow::Result<Vec<u8>>) {
        match bytes.and_then(|b| decrypt::load_sender_key(&b)) {
            Ok(cert) => {
                if !self
                    .sign
                    .signers
                    .iter()
                    .any(|c| c.fingerprint() == cert.fingerprint())
                {
                    self.sign.signers.push(cert);
                }
                self.sign.signer_notice = Status::None;
                self.sign.result = None;
            }
            Err(e) => self.sign.signer_notice = Status::Error(format!("{e:#}")),
        }
    }

    fn run_verify(&mut self) {
        let mut certs = self.sign.signers.clone();
        certs.extend(self.address_book_certs());
        self.sign.verify_notice = Status::None;
        let result = match (&self.sign.verify_file, &self.sign.verify_sig) {
            (Some(file), Some(sig)) => {
                sign::verify_file(&file.bytes, &sig.bytes, &certs).map(|check| (check, None))
            }
            _ => sign::verify_text(self.sign.verify_text.trim().as_bytes(), &certs).map(|v| {
                let content = String::from_utf8_lossy(&v.content).into_owned();
                (v.signature, Some(content))
            }),
        };
        match result {
            Ok(result) => self.sign.result = Some(result),
            Err(e) => {
                self.sign.result = None;
                self.sign.verify_notice = Status::Error(format!("{e:#}"));
            }
        }
    }

    fn verify_result_ui(&mut self, ui: &mut egui::Ui) {
        let Some((check, content)) = &self.sign.result else {
            return;
        };
        ui.separator();
        ui.heading("Result");
        let name = |cert: &Cert| self.display_name(cert);
        signature_banner(ui, check, &name);
        let mut save_signer = None;
        if let SignatureCheck::Good { signer } | SignatureCheck::KeyProblem { signer, .. } = check
            && self.store.name_for(&signer.fingerprint()).is_none()
            && ui.button("👤 Save the signer to Contacts").clicked()
        {
            save_signer = Some(signer.clone());
        }
        if let Some(content) = content {
            ui.add_space(6.0);
            ui.label(RichText::new("What the signature covers:").strong());
            ui.label(
                RichText::new("Only trust this part: text outside the signature could have been added by anyone.")
                    .weak(),
            );
            egui::ScrollArea::vertical()
                .id_salt("verified-text")
                .max_height(260.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut content.as_str())
                            .desired_width(f32::INFINITY),
                    );
                });
        }
        if let Some(signer) = save_signer {
            self.offer_new_contact(signer);
        }
    }
}

/// Asks for any file and reads it. `None` if the dialog was cancelled.
fn pick_any_file(title: &str) -> Option<Result<PickedFile, String>> {
    let path = rfd::FileDialog::new().set_title(title).pick_file()?;
    Some(
        std::fs::read(&path)
            .map(|bytes| PickedFile {
                name: file_name(&path),
                path: path.clone(),
                bytes,
            })
            .map_err(|e| format!("Could not open the file: {e}")),
    )
}

/// `file.asc` or `file.sig`, if one sits next to `file`.
fn find_signature_next_to(path: &Path) -> Option<PickedFile> {
    ["asc", "sig"].iter().find_map(|ext| {
        let mut sig = path.as_os_str().to_owned();
        sig.push(format!(".{ext}"));
        let sig = PathBuf::from(sig);
        let bytes = std::fs::read(&sig).ok()?;
        Some(PickedFile {
            name: file_name(&sig),
            path: sig,
            bytes,
        })
    })
}
