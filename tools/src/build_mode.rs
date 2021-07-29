#[derive(Clone, Copy, Debug)]
pub enum BuildMode {
    // TODO: Debug mode is not yet turned on anywhere.
    #[allow(dead_code)]
    Debug,

    // TODO: for now always use release mode to avoid this error: "LLVM
    // ERROR: Do not know how to split the result of this operator!"
    Release,
}

impl BuildMode {
    pub fn dir_name(&self) -> &'static str {
        match self {
            BuildMode::Debug => "debug",
            BuildMode::Release => "release",
        }
    }

    pub fn cargo_args(&self) -> &'static [&'static str] {
        match self {
            BuildMode::Debug => &[],
            BuildMode::Release => &["--release"],
        }
    }
}
