use std::env;
use std::path::PathBuf;
use bindgen::EnumVariation;
use cmake::Config;

fn main() {
    let lib = Config::new("ngtcp2")
        .define("ENABLE_STATIC_LIB", "ON")
        .define("ENABLE_SHARED_LIB", "OFF")
        .define("ENABLE_OPENSSL", "OFF")
        .define("BUILD_TESTING", "OFF")
        .define("CMAKE_C_VISIBILITY_PRESET", "hidden")
        .cflag("-flto")
        .build();
    println!("cargo::rustc-link-search=native={}", lib.join("lib").display());
    println!("cargo::rustc-link-lib=static=ngtcp2");


    let bindings = bindgen::Builder::default()
        .wrap_unsafe_ops(true)
        .generate_cstr(true)
        .default_enum_style(EnumVariation::Rust{non_exhaustive: false})
        .clang_arg(format!("-I{}", lib.join("include").display()))
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.

        .expect("Unable to generate bindings");
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
