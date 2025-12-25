use std::env;
use std::path::PathBuf;

fn main() {
    // Get the project root directory
    let project_root = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    
    // Add library search paths
    let build_dir = project_root.join("build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    
    // Link against the shared bindings library (built by `make bindings-shared`).
    // It already contains the core FRPC/Yamux/tools/wrapper objects.
    println!("cargo:rustc-link-lib=dylib=frpc-bindings");
    // Ensure the test binary can find the dylib at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", build_dir.display());
    
    // Link against system libraries
    println!("cargo:rustc-link-lib=dylib=pthread");
    
    // Tell cargo to invalidate the built crate whenever the C library changes
    println!("cargo:rerun-if-changed={}", project_root.join("tiny-frpc").display());
    println!("cargo:rerun-if-changed={}", build_dir.display());
}