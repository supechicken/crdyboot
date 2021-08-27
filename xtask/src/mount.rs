use anyhow::Error;
use camino::Utf8Path;
use command_run::Command;
use fehler::throws;

pub struct Mount {
    mount_point: tempfile::TempDir,
}

impl Mount {
    #[throws]
    pub fn new(device: &Utf8Path) -> Mount {
        let mount_point = tempfile::TempDir::new()?;

        Command::with_args("sudo", &["mount", device.as_str()])
            .add_arg(mount_point.path())
            .run()?;

        Mount { mount_point }
    }

    pub fn mount_point(&self) -> &Utf8Path {
        Utf8Path::from_path(self.mount_point.path()).unwrap()
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        Command::with_args("sudo", &["umount", self.mount_point().as_str()])
            .run()
            .unwrap();
    }
}
