//! Graphical user interface (egui).

use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};

use crate::keygen::{self, Algorithm, Encoding, GeneratedKey, KeyRequest, Part};

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

pub struct ComfyApp {
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
    status: Status,
}

impl Default for ComfyApp {
    fn default() -> Self {
        Self {
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
            form_grid("identity").show(ui, |ui| {
                ui.label("Name or nickname");
                ui.add(egui::TextEdit::singleline(&mut self.name).hint_text("optional"));
                ui.end_row();

                ui.label("Email");
                ui.add(egui::TextEdit::singleline(&mut self.email).hint_text("optional"));
                ui.end_row();
            });

            ui.add_space(12.0);
            self.key_type_ui(ui);
            ui.add_space(12.0);

            form_grid("options").show(ui, |ui| {
                ui.label("Expires");
                egui::ComboBox::from_id_salt("expiry")
                    .selected_text(self.expiry.label())
                    .show_ui(ui, |ui| {
                        for e in Expiry::CHOICES {
                            ui.selectable_value(&mut self.expiry, e, e.label());
                        }
                    });
                ui.end_row();

                ui.label("Passphrase");
                ui.checkbox(&mut self.use_passphrase, "Protect the secret key");
                ui.end_row();

                if self.use_passphrase {
                    ui.label("");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.passphrase)
                            .password(true)
                            .hint_text("passphrase"),
                    );
                    ui.end_row();

                    ui.label("");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.passphrase_repeat)
                            .password(true)
                            .hint_text("repeat passphrase"),
                    );
                    ui.end_row();
                }
            });

            ui.add_space(6.0);
            if keygen::user_id(&self.name, &self.email).is_none() {
                warning(
                    ui,
                    "With no name or email the key has no User ID: GnuPG/Kleopatra \
                     may refuse to import it. A nickname is enough.",
                );
            }
            if self.expiry == Expiry::Never {
                warning(
                    ui,
                    "With no expiry, keep the revocation certificate safe: it is the only \
                     way to invalidate the key if you lose it.",
                );
            }
            if !self.use_passphrase {
                warning(
                    ui,
                    "Without a passphrase, anyone who gets the secret key file can \
                     use it as you.",
                );
            }

            ui.add_space(10.0);
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

    /// Key type picker, written for people who have never used PGP:
    /// plain names first, the technical name only as a footnote.
    fn key_type_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Key type").strong());
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

        egui::CollapsingHeader::new("Why are there two?")
            .id_salt("why-two")
            .show(ui, |ui| {
                ui.label(
                    "PGP has been around since 1991. RSA is the original kind of key and \
                     every PGP program understands it. Modern keys use newer math \
                     (elliptic curves): they give the same protection with much smaller \
                     keys. GnuPG has supported them since 2014 and makes them by default \
                     since 2021.",
                );
                ui.add_space(4.0);
                ui.label(
                    "The choice only affects size, speed and which programs can read your \
                     key, not how safe your messages are.",
                );
            });
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
        let uid = key
            .cert
            .userids()
            .next()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .unwrap_or_else(|| "(no User ID)".into());
        ui.label(format!("User ID: {uid}"));

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
                ui.colored_label(Color32::from_rgb(220, 70, 70), msg);
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("comfyPGP");
                ui.label(RichText::new("OpenPGP key generator").weak());
                ui.add_space(10.0);
                self.form_ui(ui);
                self.result_ui(ui);
            });
        });
    }
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
