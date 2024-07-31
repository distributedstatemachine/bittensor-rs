use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/python_bindings.rs");

    // Print the target directory for debugging
    println!(
        "cargo:warning=Target directory: {}",
        env::var("OUT_DIR").unwrap()
    );
}
