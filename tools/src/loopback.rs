use anyhow::Error;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use fehler::throws;

pub struct PartitionPaths {
    pub efi: Utf8PathBuf,
    pub kern_a: Utf8PathBuf,
    pub kern_b: Utf8PathBuf,
}

pub struct LoopbackDevice {
    device_path: Utf8PathBuf,
}

impl LoopbackDevice {
    #[throws]
    pub fn new(disk_image_path: &Utf8Path) -> LoopbackDevice {
        let output = Command::with_args(
            "sudo",
            &[
                "losetup",
                "--find",
                "--show",
                "--partscan",
                disk_image_path.as_str(),
            ],
        )
        .enable_capture()
        .run()?;
        let device_path = output.stdout_string_lossy();
        LoopbackDevice {
            device_path: device_path.trim().into(),
        }
    }

    fn partition_device(&self, partition_num: u32) -> Utf8PathBuf {
        format!("{}p{}", self.device_path.as_str(), partition_num).into()
    }

    fn is_disk_using_partition_layout_27(&self) -> bool {
        self.partition_device(27).exists()
    }

    pub fn partition_paths(&self) -> PartitionPaths {
        let offset = if self.is_disk_using_partition_layout_27() {
            15
        } else {
            0
        };

        PartitionPaths {
            kern_a: self.partition_device(offset + 2),
            kern_b: self.partition_device(offset + 4),
            efi: self.partition_device(offset + 12),
        }
    }
}

impl Drop for LoopbackDevice {
    fn drop(&mut self) {
        Command::with_args(
            "sudo",
            &["losetup", "--detach", self.device_path.as_str()],
        )
        .run()
        .unwrap();
    }
}
