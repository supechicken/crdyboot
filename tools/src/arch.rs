use std::convert::TryInto;

pub enum Arch {
    Ia32,
    X64,
}

impl Arch {
    pub fn all() -> [Arch; 2] {
        [Arch::Ia32, Arch::X64]
    }

    pub fn all_targets() -> [&'static str; 2] {
        let targets: Vec<_> = Arch::all().iter().map(Arch::as_target).collect();
        targets.try_into().unwrap()
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
