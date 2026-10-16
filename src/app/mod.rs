//! Graphical user interface (egui).

use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};

use sequoia_openpgp::{Cert, Fingerprint};

use crate::decrypt::SignatureCheck;
use crate::keygen::{self, Algorithm, Encoding, GeneratedKey, KeyRequest, Part};
use crate::store::{self, Store};
use crate::{decrypt, encrypt};

mod book;
mod decrypt_tab;
mod encrypt_tab;
mod generate;

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

#[derive(Default)]
enum Status {
    #[default]
    None,
    Info(String),
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Encrypt,
    Decrypt,
    Contacts,
    MyKeys,
    Generate,
}

pub struct ComfyApp {
    tab: Tab,
    store: Store,
    book: book::BookState,

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
    /// Name to save the new key under in My keys.
    gen_save_name: String,
    gen_saved_as: Option<String>,

    /// One of the user's keys, also encrypted to so they can read the
    /// message later.
    enc_from: Option<Fingerprint>,
    enc_recipients: Vec<Cert>,
    enc_message: String,
    /// A file to encrypt instead of the text: (file name, contents).
    enc_file: Option<(String, Vec<u8>)>,
    enc_output: Option<String>,
    /// Feedback on adding recipients, shown right under the buttons.
    enc_notice: Status,

    dec_key: Option<Cert>,
    /// The key was picked automatically from the message's recipients.
    dec_key_auto: bool,
    /// The message is for none of the saved keys.
    dec_no_match: bool,
    dec_message: String,
    /// A binary message opened from a file: (file name, contents).
    dec_file: Option<(String, Vec<u8>)>,
    dec_passphrase: String,
    /// Public keys of people who may have signed the message.
    dec_senders: Vec<Cert>,
    dec_sender_notice: Status,
    dec_output: Option<decrypt::Decrypted>,

    status: Status,
}

impl ComfyApp {
    pub fn new() -> Self {
        let path = store::default_path()
            .unwrap_or_else(|_| std::path::PathBuf::from("comfyPGP-address-book.json"));
        let (store, warning) = Store::load(path);
        let tab = if store.my_keys.is_empty() {
            Tab::Generate
        } else {
            Tab::Encrypt
        };
        let enc_from = store.my_keys.first().map(|e| e.cert.fingerprint());
        Self {
            tab,
            store,
            book: Default::default(),
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
            gen_save_name: String::new(),
            gen_saved_as: None,
            enc_from,
            enc_recipients: Vec::new(),
            enc_message: String::new(),
            enc_file: None,
            enc_output: None,
            enc_notice: Status::None,
            dec_key: None,
            dec_key_auto: false,
            dec_no_match: false,
            dec_message: String::new(),
            dec_file: None,
            dec_passphrase: String::new(),
            dec_senders: Vec::new(),
            dec_sender_notice: Status::None,
            dec_output: None,
            status: match warning {
                Some(w) => Status::Error(w),
                None => Status::None,
            },
        }
    }

    /// Saves the address book, reporting any problem in the status bar.
    fn persist(&mut self) {
        if let Err(e) = self.store.save() {
            self.status = Status::Error(format!("Could not save your address book: {e:#}"));
        }
    }

    /// Keeps choices that point into My keys valid after it changes.
    fn after_my_keys_changed(&mut self) {
        let exists = |f: &Fingerprint| {
            self.store
                .my_keys
                .iter()
                .any(|e| &e.cert.fingerprint() == f)
        };
        if !self.enc_from.as_ref().is_some_and(exists) {
            self.enc_from = self.store.my_keys.first().map(|e| e.cert.fingerprint());
        }
    }

    /// The name the user gave this key, or its User ID.
    fn display_name(&self, cert: &Cert) -> String {
        self.store
            .name_for(&cert.fingerprint())
            .map(String::from)
            .unwrap_or_else(|| user_id_of(cert))
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
                    let tabs = [
                        (Tab::Encrypt, "🔒 Encrypt"),
                        (Tab::Decrypt, "🔓 Decrypt"),
                        (Tab::Contacts, "👤 Contacts"),
                        (Tab::MyKeys, "🗝 My keys"),
                        (Tab::Generate, "✨ New key"),
                    ];
                    for (tab, label) in tabs {
                        ui.selectable_value(&mut self.tab, tab, RichText::new(label).size(15.0));
                    }
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
                    Tab::Contacts => self.contacts_ui(ui),
                    Tab::MyKeys => self.my_keys_ui(ui),
                }
            });
        });
    }
}

const SECTION_GAP: f32 = 16.0;
const ERROR_COLOR: Color32 = Color32::from_rgb(220, 70, 70);
const GOOD_COLOR: Color32 = Color32::from_rgb(60, 140, 90);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 150, 40);

fn user_id_of(cert: &Cert) -> String {
    cert.userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .unwrap_or_else(|| "(no User ID)".into())
}

/// One key in a list: its name, then User ID and fingerprint, with a ✕
/// to remove it. Returns `true` when ✕ is clicked.
fn cert_row(ui: &mut egui::Ui, name: &str, cert: &Cert) -> bool {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("✔ {name}")).strong());
        ui.label(RichText::new(key_details(cert)).weak());
        ui.small_button("✕").on_hover_text("Remove").clicked()
    })
    .inner
}

/// "User ID · fingerprint", to tell keys apart.
fn key_details(cert: &Cert) -> String {
    format!(
        "{}  ·  {}",
        user_id_of(cert),
        keygen::pretty_fingerprint(cert)
    )
}

fn notice_ui(ui: &mut egui::Ui, notice: &Status) {
    match notice {
        Status::None => {}
        Status::Info(msg) => {
            ui.label(RichText::new(msg).weak());
        }
        Status::Error(msg) => {
            ui.colored_label(ERROR_COLOR, msg);
        }
    }
}

/// Asks for a key file. `None` if the dialog was cancelled.
fn pick_key_file(title: &str) -> Option<anyhow::Result<Vec<u8>>> {
    let path = rfd::FileDialog::new()
        .set_title(title)
        .add_filter(
            "PGP key (.asc, .txt, .gpg, .key)",
            &["asc", "txt", "gpg", "key"],
        )
        .add_filter("All files", &["*"])
        .pick_file()?;
    Some(std::fs::read(path).map_err(Into::into))
}

fn clipboard_key() -> anyhow::Result<Vec<u8>> {
    match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
        Ok(text) => Ok(text.trim().as_bytes().to_vec()),
        Err(_) => anyhow::bail!("The clipboard is empty. Copy a public key first."),
    }
}

/// The colored box above a decrypted message saying who signed it.
/// `name` gives the name the user knows a key by.
fn signature_banner(ui: &mut egui::Ui, check: &SignatureCheck, name: &dyn Fn(&Cert) -> String) {
    let green = GOOD_COLOR;
    let amber = WARN_COLOR;
    let grey = ui.visuals().weak_text_color();

    let (color, title, detail): (Color32, String, String) = match check {
        SignatureCheck::Good { signer } => (
            green,
            format!("✔ Signed by {}", name(signer)),
            format!("Key: {}", key_details(signer)),
        ),
        SignatureCheck::UnknownSigner { issuer } => (
            amber,
            "⚠ Signed, but you don't have the sender's key".into(),
            match issuer {
                Some(id) => format!(
                    "Save the sender in Contacts, or add their key above, and decrypt \
                     again.\nSigner's key: {id}"
                ),
                None => "Save the sender in Contacts, or add their key above, and decrypt \
                         again."
                    .into(),
            },
        ),
        SignatureCheck::KeyProblem { signer, reason } => (
            amber,
            format!(
                "⚠ Signed by {}, but there is a problem with their key",
                name(signer)
            ),
            (*reason).into(),
        ),
        SignatureCheck::Bad { signer } => (
            ERROR_COLOR,
            "✖ The signature is not valid".into(),
            match signer {
                Some(signer) => format!(
                    "The message may have been changed after {} signed it. Do not trust it.",
                    name(signer)
                ),
                None => {
                    "The message may have been changed after it was signed. Do not trust it.".into()
                }
            },
        ),
        SignatureCheck::NotSigned => (
            grey,
            "Not signed".into(),
            "There is no way to know who wrote this message.".into(),
        ),
    };

    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(6.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).strong().color(color));
            ui.label(detail);
        });

    if !matches!(check, SignatureCheck::NotSigned) {
        explainer(
            ui,
            "Can I trust this?",
            &[
                "A valid signature proves two things: the message was written with this \
                 key, and nobody changed it on the way.",
                "It does not prove who owns the key. Anyone can create a key with any name. \
                 The first time you get someone's key, compare its fingerprint with them \
                 through another channel: in person, by phone, or on their website.",
            ],
        );
    }
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
