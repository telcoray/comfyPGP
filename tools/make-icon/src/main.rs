//! Renders `assets/icon.svg` into:
//! - `assets/comfypgp.ico`: every size Windows uses, embedded in the .exe;
//! - `assets/icon-256.png`: the window and taskbar icon.
//!
//! Run it after changing the SVG: `cargo run --manifest-path tools/make-icon/Cargo.toml`
//! Pass a folder to also write a PNG of every size there, to look at them.

use std::fs::File;
use std::path::{Path, PathBuf};

use resvg::{tiny_skia, usvg};

const SIZES: [u32; 9] = [16, 20, 24, 32, 40, 48, 64, 128, 256];

fn render(tree: &usvg::Tree, size: u32) -> tiny_skia::Pixmap {
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("valid size");
    let scale = size as f32 / tree.size().width();
    resvg::render(
        tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    pixmap
}

/// Straight (not premultiplied) RGBA, as the .ico format wants.
fn rgba(pixmap: &tiny_skia::Pixmap) -> Vec<u8> {
    pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

fn main() {
    let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets");
    let previews: Option<PathBuf> = std::env::args().nth(1).map(PathBuf::from);

    let svg = std::fs::read(assets.join("icon.svg")).expect("assets/icon.svg");
    let tree = usvg::Tree::from_data(&svg, &usvg::Options::default()).expect("valid SVG");

    let mut icon = ico::IconDir::new(ico::ResourceType::Icon);
    for size in SIZES {
        let pixmap = render(&tree, size);
        let image = ico::IconImage::from_rgba_data(size, size, rgba(&pixmap));
        icon.add_entry(ico::IconDirEntry::encode(&image).expect("encode icon"));
        if size == 256 {
            pixmap
                .save_png(assets.join("icon-256.png"))
                .expect("write icon-256.png");
        }
        if let Some(dir) = &previews {
            std::fs::create_dir_all(dir).expect("preview folder");
            pixmap
                .save_png(dir.join(format!("icon-{size}.png")))
                .expect("write preview");
        }
    }
    let file = File::create(assets.join("comfypgp.ico")).expect("create comfypgp.ico");
    icon.write(file).expect("write comfypgp.ico");
    println!("Wrote assets/comfypgp.ico and assets/icon-256.png");
}
