//! Rebuilds the crate when a migration changes, since `sqlx::migrate!` embeds them.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
