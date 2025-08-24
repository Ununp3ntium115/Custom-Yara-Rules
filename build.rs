use std::env;

fn main() {
    // Set build-time environment variables
    println!("cargo:rustc-env=BUILD_TARGET={}", env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()));
    println!("cargo:rustc-env=BUILD_PROFILE={}", env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string()));
    
    // Rerun if build script changes
    println!("cargo:rerun-if-changed=build.rs");
}