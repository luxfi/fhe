use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let include_path = PathBuf::from(&manifest_dir).join("../c/include");
    let lib_path = PathBuf::from(&manifest_dir).join("../c/lib");

    // Link to the LuxFHE library
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=dylib=luxfhe");

    // macOS specific
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=Security");
    }

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header(include_path.join("luxfhe.h").to_str().unwrap())
        .clang_arg(format!("-I{}", include_path.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_comments(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_function("luxfhe_.*")
        .allowlist_type("LuxFHE_.*")
        .allowlist_var("LUXFHE_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
