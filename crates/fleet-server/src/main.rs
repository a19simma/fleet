//! fleet-server: the Fleet server. Stub that prints its version.

use std::io::Write;

fn main() {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "fleet-server {}", env!("CARGO_PKG_VERSION"));
}
