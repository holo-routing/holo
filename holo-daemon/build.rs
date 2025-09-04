fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Try to get short git commit hash.
    rustc_tools_util::setup_version_info!();

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
