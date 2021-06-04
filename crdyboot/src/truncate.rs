// TODO: this avoids some linker errors; this code should never
// actually be called.

#[no_mangle]
pub extern "C" fn __truncdfsf2(_a: f64) -> f32 {
    panic!();
}

#[no_mangle]
pub extern "C" fn fmod(_a: f64) -> f32 {
    panic!();
}
