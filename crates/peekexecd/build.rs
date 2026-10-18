fn main() {
    // Link libpam by its runtime soname so building needs no -dev package.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=dylib:+verbatim=libpam.so.0");
    }
}
