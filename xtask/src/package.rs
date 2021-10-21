/// Packages in the root workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Package {
    Crdyboot,
    Enroller,
    SbatGen,
    Tools,
    Vboot,
}

impl Package {
    /// Get all packages.
    pub fn all() -> [Package; 5] {
        use Package::*;
        [Crdyboot, Enroller, SbatGen, Tools, Vboot]
    }

    /// Get the package's crate name.
    pub fn name(&self) -> &'static str {
        use Package::*;
        match self {
            Crdyboot => "crdyboot",
            Enroller => "enroller",
            SbatGen => "sbat_gen",
            Tools => "crdyboot_tools",
            Vboot => "vboot",
        }
    }
}
