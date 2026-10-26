// Embeds the icon and version details in the Windows .exe.
// The icon comes from assets/icon.svg, rendered by tools/make-icon.

fn main() {
    println!("cargo:rerun-if-changed=assets/comfypgp.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/comfypgp.ico")
        .set("ProductName", "comfyPGP")
        .set("FileDescription", "comfyPGP - a friendly OpenPGP app");
    res.compile().expect("could not embed the Windows icon");
}
