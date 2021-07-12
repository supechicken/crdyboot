pub enum Arch {
    Ia32,
    X64,
}

impl Arch {
    pub fn all() -> [Arch; 2] {
        [Arch::Ia32, Arch::X64]
    }

    pub fn as_target(&self) -> &'static str {
        match self {
            Arch::Ia32 => "i686-unknown-uefi",
            Arch::X64 => "x86_64-unknown-uefi",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::Ia32 => "ia32",
            Arch::X64 => "x64",
        }
    }
}
