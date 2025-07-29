use std::process::Command;
use std::str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Try to get short git commit hash.
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        && output.status.success()
        && let Ok(hash) = str::from_utf8(&output.stdout)
    {
        println!("cargo:rustc-env=GIT_BUILD_HASH={}", hash.trim());
    }
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    // Compile protobuf definitions.
    tonic_build::configure()
        .build_client(false)
        .compile_protos(
            &[
                "../proto/holo.proto",
                "../proto/gnmi_ext.proto",
                "../proto/gnmi.proto",
            ],
            &["../proto"],
        )?;

    Ok(())
}
