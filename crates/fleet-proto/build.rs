//! Compiles `proto/fleet/v1/fleet.proto` with the vendored `protoc`.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.skip_debug(["fleet.v1.PutCredentialRequest", "fleet.v1.JobCredential"]);
    tonic_prost_build::configure().compile_with_config(
        config,
        &["proto/fleet/v1/fleet.proto"],
        &["proto"],
    )?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
