include!(concat!(env!("OUT_DIR"), "/yang.rs"));

// Shortcuts to commonly used YANG paths.
#[cfg(feature = "routing")]
pub use routing::control_plane_protocols::control_plane_protocol;
