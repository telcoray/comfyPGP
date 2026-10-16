//! The Contacts and My keys tabs: the address book.

use super::*;
use sequoia_openpgp::serialize::SerializeInto;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum List {
    MyKeys,
    Contacts,
}

#[derive(Default)]
pub(super) struct BookState {
    /// The contact being added.
    pub(super) new_contact_name: String,
    pub(super) new_contact_key: Option<Cert>,
    contact_notice: Status,
    /// A secret key being imported into My keys, waiting for its name.
    import_key: Option<Cert>,
    import_name: String,
    my_keys_notice: Status,
    /// The entry being renamed, and its new name.
    renaming: Option<(List, Fingerprint, String)>,
    /// The entry waiting for a second click to be removed.
    confirm_remove: Option<(List, Fingerprint)>,
    /// The key whose passphrase is being set or changed.
    passphrase_form: Option<PassphraseForm>,
}

struct PassphraseForm {
    fpr: Fingerprint,
    current: String,
    new: String,
    repeat: String,
    error: Option<String>,
}

enum Action {
    StartRename,
    Rename(String),
    CancelRename,
    CopyPublic,
    SavePublic,
    SaveSecret,
    StartPassphrase,
    SavePassphrase,
    CancelPassphrase,
    AskRemove,
    Remove,
    CancelRemove,
}

impl ComfyApp {
    pub(super) fn contacts_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "Contacts");
        if self.store.contacts.is_empty() {
            ui.label(RichText::new("No contacts yet. Add someone below.").weak());
        }
        self.entry_rows(ui, List::Contacts);

        ui.add_space(SECTION_GAP);
        section_header(ui, "Add a contact");
        form_grid("new-contact").show(ui, |ui| {
            ui.label("Name");
            ui.add(
                egui::TextEdit::singleline(&mut self.book.new_contact_name).hint_text("e.g. Mario"),
            );
            ui.end_row();
        });
        match &self.book.new_contact_key {
            Some(cert) => {
                ui.label(RichText::new(format!("✔ {}", key_details(cert))).weak());
                key_warnings(ui, cert, List::Contacts);
            }
            None => {
                ui.label(RichText::new("Now add their public key.").weak());
            }
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("📂 Open public key file…").clicked()
                && let Some(bytes) = pick_key_file("Open your contact's public key")
            {
                self.set_new_contact_key(bytes);
            }
            if ui.button("📋 Paste public key").clicked() {
                self.set_new_contact_key(clipboard_key());
            }
        });
        let ready =
            self.book.new_contact_key.is_some() && !self.book.new_contact_name.trim().is_empty();
        if ui
            .add_enabled(ready, egui::Button::new("👤 Save contact"))
            .clicked()
        {
            self.save_new_contact();
        }
        notice_ui(ui, &self.book.contact_notice);
        explainer(
            ui,
            "How do I get someone's key?",
            &[
                "Ask them for their public key: it is safe to share. It is a block of text \
                 that starts with -----BEGIN PGP PUBLIC KEY BLOCK-----.",
                "Before trusting it, compare its fingerprint with them through another \
                 channel: in person, by phone, or on their website.",
            ],
        );
    }

    pub(super) fn my_keys_ui(&mut self, ui: &mut egui::Ui) {
        section_header(ui, "My keys");
        if self.store.my_keys.is_empty() {
            ui.label(
                RichText::new(
                    "No keys yet. Create one in New key, or import one you already have.",
                )
                .weak(),
            );
        }
        self.entry_rows(ui, List::MyKeys);

        ui.add_space(SECTION_GAP);
        section_header(ui, "Import a key you already have");
        match &self.book.import_key {
            None => {
                if ui.button("📂 Open secret key file…").clicked()
                    && let Some(bytes) = pick_key_file("Open your secret key")
                {
                    match bytes.and_then(|b| decrypt::load_secret_key(&b)) {
                        Ok(cert) => {
                            self.book.import_name = suggested_name(&cert);
                            self.book.import_key = Some(cert);
                            self.book.my_keys_notice = Status::None;
                        }
                        Err(e) => {
                            let msg = format!("{e:#}").replace(
                                "To decrypt you need your secret key.",
                                "Add it in Contacts instead.",
                            );
                            self.book.my_keys_notice = Status::Error(msg);
                        }
                    }
                }
            }
            Some(cert) => {
                ui.label(RichText::new(format!("✔ {}", key_details(cert))).weak());
                key_warnings(ui, cert, List::MyKeys);
                let mut save = false;
                let mut cancel = false;
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.book.import_name)
                            .hint_text("e.g. work, friends"),
                    );
                    save = ui.button("🗝 Save to My keys").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
                if save {
                    let cert = cert.clone();
                    let name = self.book.import_name.clone();
                    match self.store.add_my_key(&name, cert) {
                        Ok(()) => {
                            self.book.import_key = None;
                            self.book.my_keys_notice =
                                Status::Info(format!("Saved as \"{}\".", name.trim()));
                            self.after_my_keys_changed();
                            self.persist();
                        }
                        Err(e) => self.book.my_keys_notice = Status::Error(format!("{e:#}")),
                    }
                }
                if cancel {
                    self.book.import_key = None;
                }
            }
        }
        notice_ui(ui, &self.book.my_keys_notice);
        let folder = self
            .store
            .path()
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        explainer(
            ui,
            "Where are my keys kept?",
            &[
                &format!("comfyPGP keeps a copy of your keys in {folder}."),
                "Keys with a passphrase stay locked there. Keys without one can be used by \
                 anyone who can read your files.",
                "Keep your own backup too: use \"Save secret key…\" and store the file \
                 somewhere safe, like a USB stick.",
            ],
        );
    }

    /// The saved keys of one list, each with its buttons.
    fn entry_rows(&mut self, ui: &mut egui::Ui, list: List) {
        let entries = match list {
            List::MyKeys => &self.store.my_keys,
            List::Contacts => &self.store.contacts,
        };
        let mut action = None;
        for entry in entries {
            let fpr = entry.cert.fingerprint();
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let renaming = match &mut self.book.renaming {
                    Some((l, f, name)) if *l == list && *f == fpr => Some(name),
                    _ => None,
                };
                match renaming {
                    Some(new_name) => {
                        ui.horizontal(|ui| {
                            let edit = ui.text_edit_singleline(new_name);
                            let enter =
                                edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if ui.button("✔ Save").clicked() || enter {
                                action = Some((fpr.clone(), Action::Rename(new_name.clone())));
                            }
                            if ui.button("Cancel").clicked() {
                                action = Some((fpr.clone(), Action::CancelRename));
                            }
                        });
                    }
                    None => {
                        ui.label(RichText::new(&entry.name).strong().size(15.0));
                    }
                }
                ui.label(RichText::new(key_details(&entry.cert)).weak());
                key_warnings(ui, &entry.cert, list);
                let locked = has_passphrase(&entry.cert);
                if let Some(form) = &mut self.book.passphrase_form
                    && form.fpr == fpr
                    && let Some(a) = passphrase_form_ui(ui, form, locked)
                {
                    action = Some((fpr.clone(), a));
                }

                ui.horizontal_wrapped(|ui| {
                    if ui.small_button("✏ Rename").clicked() {
                        action = Some((fpr.clone(), Action::StartRename));
                    }
                    if ui.small_button("📋 Copy public key").clicked() {
                        action = Some((fpr.clone(), Action::CopyPublic));
                    }
                    if ui.small_button("💾 Save public key…").clicked() {
                        action = Some((fpr.clone(), Action::SavePublic));
                    }
                    let label = if locked {
                        "🔒 Change passphrase…"
                    } else {
                        "🔒 Set passphrase…"
                    };
                    if list == List::MyKeys && ui.small_button(label).clicked() {
                        action = Some((fpr.clone(), Action::StartPassphrase));
                    }
                    if list == List::MyKeys && ui.small_button("💾 Save secret key…").clicked()
                    {
                        action = Some((fpr.clone(), Action::SaveSecret));
                    }
                    let confirming = self.book.confirm_remove == Some((list, fpr.clone()));
                    if confirming {
                        let sure = egui::Button::new(
                            RichText::new(format!("Remove \"{}\" for good", entry.name))
                                .color(ERROR_COLOR),
                        )
                        .small();
                        if ui.add(sure).clicked() {
                            action = Some((fpr.clone(), Action::Remove));
                        }
                        if ui.small_button("Cancel").clicked() {
                            action = Some((fpr.clone(), Action::CancelRemove));
                        }
                    } else if ui.small_button("🗑 Remove").clicked() {
                        action = Some((fpr.clone(), Action::AskRemove));
                    }
                });
            });
        }
        if let Some((fpr, action)) = action {
            self.apply(list, fpr, action);
        }
    }

    fn apply(&mut self, list: List, fpr: Fingerprint, action: Action) {
        let entries = match list {
            List::MyKeys => &mut self.store.my_keys,
            List::Contacts => &mut self.store.contacts,
        };
        let Some(index) = entries.iter().position(|e| e.cert.fingerprint() == fpr) else {
            return;
        };
        let name = entries[index].name.clone();
        let cert = entries[index].cert.clone();
        match action {
            Action::StartRename => self.book.renaming = Some((list, fpr, name)),
            Action::CancelRename => self.book.renaming = None,
            Action::Rename(new_name) => match store::valid_name(&new_name) {
                Ok(new_name) => {
                    entries[index].name = new_name;
                    self.book.renaming = None;
                    self.persist();
                }
                Err(e) => self.status = Status::Error(format!("{e:#}")),
            },
            Action::CopyPublic => {
                let text = armored_public(&cert);
                self.status = match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
                    Ok(()) => Status::Info(format!("Public key of \"{name}\" copied.")),
                    Err(e) => Status::Error(format!("Could not copy: {e}")),
                };
            }
            Action::SavePublic => {
                let text = armored_public(&cert);
                self.save_text(
                    &format!("{name}-public.asc"),
                    "Save public key",
                    text.as_bytes(),
                );
            }
            Action::StartPassphrase => {
                self.book.passphrase_form = Some(PassphraseForm {
                    fpr,
                    current: String::new(),
                    new: String::new(),
                    repeat: String::new(),
                    error: None,
                });
            }
            Action::CancelPassphrase => self.book.passphrase_form = None,
            Action::SavePassphrase => {
                let Some(form) = &mut self.book.passphrase_form else {
                    return;
                };
                if form.new.is_empty() {
                    form.error = Some("Enter the new passphrase.".into());
                    return;
                }
                if form.new != form.repeat {
                    form.error = Some("The new passphrases do not match.".into());
                    return;
                }
                match keygen::set_passphrase(&cert, Some(&form.current), &form.new) {
                    Ok(locked) => {
                        entries[index].cert = locked.clone();
                        self.book.passphrase_form = None;
                        if self
                            .dec_key
                            .as_ref()
                            .is_some_and(|c| c.fingerprint() == locked.fingerprint())
                        {
                            self.dec_key = Some(locked);
                            self.dec_passphrase.clear();
                        }
                        self.book.my_keys_notice = Status::Info(format!(
                            "Passphrase saved for \"{name}\". If you use this key in other \
                             apps, save the secret key again and import it there."
                        ));
                        self.persist();
                    }
                    Err(e) => form.error = Some(format!("{e:#}")),
                }
            }
            Action::SaveSecret => match cert.as_tsk().armored().to_vec() {
                Ok(bytes) => {
                    self.save_text(&format!("{name}-secret.asc"), "Save SECRET key", &bytes)
                }
                Err(e) => self.status = Status::Error(format!("{e:#}")),
            },
            Action::AskRemove => self.book.confirm_remove = Some((list, fpr)),
            Action::CancelRemove => self.book.confirm_remove = None,
            Action::Remove => {
                entries.remove(index);
                self.book.confirm_remove = None;
                if list == List::MyKeys {
                    self.after_my_keys_changed();
                }
                self.status = Status::Info(format!("\"{name}\" removed."));
                self.persist();
            }
        }
    }

    pub(super) fn save_text(&mut self, file_name: &str, title: &str, bytes: &[u8]) {
        let Some(path) = rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(file_name)
            .add_filter("ASCII armored text (.asc)", &["asc"])
            .add_filter("Text (.txt)", &["txt"])
            .save_file()
        else {
            return;
        };
        self.status = match std::fs::write(&path, bytes) {
            Ok(()) => Status::Info(format!("Saved to {}", path.display())),
            Err(e) => Status::Error(format!("Could not save: {e}")),
        };
    }

    fn set_new_contact_key(&mut self, bytes: anyhow::Result<Vec<u8>>) {
        match bytes.and_then(|b| decrypt::load_sender_key(&b)) {
            Ok(cert) => {
                if self.book.new_contact_name.trim().is_empty() {
                    self.book.new_contact_name = suggested_name(&cert);
                }
                self.book.new_contact_key = Some(cert);
                self.book.contact_notice = Status::None;
            }
            Err(e) => self.book.contact_notice = Status::Error(format!("{e:#}")),
        }
    }

    fn save_new_contact(&mut self) {
        let Some(cert) = self.book.new_contact_key.clone() else {
            return;
        };
        let name = self.book.new_contact_name.clone();
        match self.store.add_contact(&name, cert) {
            Ok(()) => {
                self.book.new_contact_key = None;
                self.book.new_contact_name.clear();
                self.book.contact_notice = Status::Info(format!("\"{}\" saved.", name.trim()));
                self.persist();
            }
            Err(e) => self.book.contact_notice = Status::Error(format!("{e:#}")),
        }
    }

    /// Opens Contacts with this key ready to be saved.
    pub(super) fn offer_new_contact(&mut self, cert: Cert) {
        self.book.new_contact_name = suggested_name(&cert);
        self.book.new_contact_key = Some(cert);
        self.book.contact_notice = Status::Info("Give the contact a name and save it.".into());
        self.tab = Tab::Contacts;
    }
}

/// Whether any secret part of the key is locked with a passphrase.
fn has_passphrase(cert: &Cert) -> bool {
    cert.keys()
        .secret()
        .any(|ka| ka.key().secret().is_encrypted())
}

/// The form to set or change a key's passphrase, inside its row.
fn passphrase_form_ui(
    ui: &mut egui::Ui,
    form: &mut PassphraseForm,
    locked: bool,
) -> Option<Action> {
    let mut action = None;
    ui.add_space(4.0);
    form_grid(&format!("passphrase-{}", form.fpr)).show(ui, |ui| {
        if locked {
            ui.label("Current passphrase");
            ui.add(egui::TextEdit::singleline(&mut form.current).password(true));
            ui.end_row();
        }
        ui.label("New passphrase");
        ui.add(egui::TextEdit::singleline(&mut form.new).password(true));
        ui.end_row();
        ui.label("Repeat");
        ui.add(egui::TextEdit::singleline(&mut form.repeat).password(true));
        ui.end_row();
    });
    ui.horizontal(|ui| {
        if ui.button("Save passphrase").clicked() {
            action = Some(Action::SavePassphrase);
        }
        if ui.button("Cancel").clicked() {
            action = Some(Action::CancelPassphrase);
        }
    });
    if let Some(error) = &form.error {
        ui.colored_label(ERROR_COLOR, error);
    }
    ui.add_space(4.0);
    action
}

/// Things worth knowing about a saved key, as warnings under it.
fn key_warnings(ui: &mut egui::Ui, cert: &Cert, list: List) {
    if list == List::MyKeys && !decrypt::needs_passphrase(cert) {
        warning(
            ui,
            "No passphrase: anyone who can read your files can use this key.",
        );
    }
    if let Err(e) = encrypt::check_can_encrypt(cert) {
        warning(ui, &format!("{e:#}"));
    } else if encrypt::uses_old_technology(cert) {
        warning(
            ui,
            "This key uses old technology (SHA-1). It still works, but a newer key is better.",
        );
    }
}

fn armored_public(cert: &Cert) -> String {
    cert.clone()
        .strip_secret_key_material()
        .armored()
        .to_vec()
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// A starting name for a key: the name in its User ID, or its email.
fn suggested_name(cert: &Cert) -> String {
    let Some(uid) = cert.userids().next() else {
        return String::new();
    };
    let uid = String::from_utf8_lossy(uid.userid().value()).into_owned();
    match uid.split_once('<') {
        Some((name, _)) if !name.trim().is_empty() => name.trim().to_string(),
        Some((_, email)) => email.trim_end_matches('>').trim().to_string(),
        None => uid.trim().to_string(),
    }
}
