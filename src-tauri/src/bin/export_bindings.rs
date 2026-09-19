//! Regenerates the TS IPC contract. Run from the repo root via
//! `npm run gen:bindings` (or pass an explicit output path).

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "src/bindings.ts".into());
    interflow_gui::export_bindings(&path).expect("failed to export bindings");
    println!("bindings written to {path}");
}
