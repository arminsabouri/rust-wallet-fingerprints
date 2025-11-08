fn main() {
    #[cfg(feature = "ffi")]
    uniffi::uniffi_bindgen_main();
    #[cfg(not(feature = "ffi"))]
    {
        panic!("ffi feature is not enabled.");
    }
}
