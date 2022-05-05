use alloc::borrow::Cow;
use alloc::string::String;
use core::{slice, str};
use log::info;
use printf_compat as printf;

unsafe fn c_str_len(mut s: *const u8) -> usize {
    let mut len = 0;
    while *s != 0 {
        len += 1;
        s = s.add(1);
    }
    len
}

unsafe fn str_from_c_str<'a>(s: *const u8) -> Cow<'a, str> {
    let bytes = slice::from_raw_parts(s.cast::<u8>(), c_str_len(s));
    String::from_utf8_lossy(bytes)
}

/// Write a printf-style message to the log at the info level. Called
/// by vboot_reference for printing.
#[no_mangle]
unsafe extern "C" fn vb2ex_printf(
    func: *const u8,
    fmt: *const u8,
    mut args: ...
) {
    // TODO: could set the function into the log record directly
    // instead of formatting it as part of the message.
    let mut output = String::new();

    let func = str_from_c_str(func);
    printf::format(
        fmt.cast::<i8>(),
        args.as_va_list(),
        printf::output::fmt_write(&mut output),
    );
    // Strip the trailing newline if present since the logger will add
    // one for us. If the input doesn't end in a newline the log
    // output will be split onto a new line anyway, which isn't
    // desired but is OK since this is just for debug output.
    let stripped = output.strip_suffix('\n').unwrap_or(&output);

    info!("{} {}", func, stripped);
}
