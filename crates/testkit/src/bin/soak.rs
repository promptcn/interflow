//! Soak long-running gate CLI entry (backlog §1.7).
//!
//! Run: `just soak [-- args]` (builds the release interflow-mesh automatically first),
//! or `cargo run --release -p interflow-testkit --bin soak -- [--quick]`.
//! See the `interflow_testkit::soak::runner` module docs for the assertions and their
//! criteria.

use clap::Parser;
use interflow_testkit::soak::runner::{self, SoakArgs};

#[tokio::main]
async fn main() {
    // A standalone runner, not a libtest queue: said before the first
    // cert/stack construction trips the nextest guard.
    interflow_testkit::declare_standalone_runner();
    let args = SoakArgs::parse();
    let outcome = runner::run(args).await;
    if !outcome.pass {
        eprintln!("soak gate verdict: FAIL (exit 1)");
        std::process::exit(1);
    }
    println!("soak gate verdict: PASS");
}
