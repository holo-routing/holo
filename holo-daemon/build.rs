fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_client(false).compile(
        &[
            "../proto/holo.proto",
            "../proto/gnmi_ext.proto",
            "../proto/gnmi.proto",
        ],
        &["../proto"],
    )?;

    Ok(())
}
