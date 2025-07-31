// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::arch::Arch;
use crate::config::{self, Config};
use crate::network::GsResource;
use crate::qemu::{Display, QemuOpts};
use crate::util::check_sha256_hash;
use crate::{copy_file, gen_disk, run_build_enroller, secure_boot, Action, SetupAction};
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use command_run::Command;
use tempfile::TempDir;

/// Bump this version any time the setup step needs to be re-run.
const SETUP_VERSION: u32 = 18;

const VBOOT_REFERENCE_REPO: &str =
    "https://chromium.googlesource.com/chromiumos/platform/vboot_reference";
const VBOOT_REFERENCE_REV: &str = "50bb82087123e3362103ad2d4a3e6a819d875a6e";

const CHROMEOS_IMAGE_ARCHIVE_BUCKET: &str = "chromeos-image-archive";
const CHROMEOS_LOCALMIRROR_BUCKET: &str = "chromeos-localmirror";

struct RepoRev {
    repo: &'static str,
    rev: &'static str,
    dir: Utf8PathBuf,
}

fn init_repo(repo: RepoRev) -> Result<()> {
    // Clone the repo if it doesn't exist.
    if !repo.dir.exists() {
        Command::with_args("git", ["clone", repo.repo, repo.dir.as_str()]).run()?;
    }

    // Get the commit that is currently checked out.
    let output = Command::with_args("git", ["-C", repo.dir.as_str(), "rev-parse", "HEAD"])
        .enable_capture()
        .run()?;
    let stdout = String::from_utf8(output.stdout)?;
    let current_commit = stdout.trim();

    // Update the checkout if necessary.
    if current_commit != repo.rev {
        // Ensure the revision has been fetched.
        Command::with_args(
            "git",
            ["-C", repo.dir.as_str(), "fetch", "origin", repo.rev],
        )
        .run()?;

        Command::with_args("git", ["-C", repo.dir.as_str(), "checkout", repo.rev]).run()?;
    }

    Ok(())
}

fn init_repos(conf: &Config) -> Result<()> {
    let repos = [
        RepoRev {
            repo: VBOOT_REFERENCE_REPO,
            rev: VBOOT_REFERENCE_REV,
            dir: conf.vboot_reference_path(),
        },
        RepoRev {
            repo: "https://android.googlesource.com/platform/system/tools/mkbootimg",
            rev: "910c9b699c985d7bb4278b3a34c71e682ee5aeb6",
            dir: conf.third_party_path().join("mkbootimg"),
        },
        RepoRev {
            repo: "https://android.googlesource.com/platform/external/avb",
            rev: "49f8d4549103f753549003804b0253677054f0b9",
            dir: conf.third_party_path().join("avb"),
        },
    ];

    for repo in repos {
        init_repo(repo)?
    }
    Ok(())
}

fn download_and_unpack_test_data(conf: &Config) -> Result<()> {
    let tmp_dir = TempDir::new_in(conf.workspace_path())?;
    let tmp_dir = Utf8Path::from_path(tmp_dir.path()).unwrap();
    let hash = config::TEST_DATA_HASH;
    let test_data_file_name = format!("crdyboot_test_data_{}.tar.xz", &hash[..8]);
    let test_data_src_path = tmp_dir.join(&test_data_file_name);

    // Download the test data tarball.
    GsResource::new_public(
        CHROMEOS_LOCALMIRROR_BUCKET,
        format!("distfiles/{test_data_file_name}"),
    )
    .download_to_file(&test_data_src_path)?;

    check_sha256_hash(&test_data_src_path, config::TEST_DATA_HASH)?;

    // Unpack the test data.
    Command::with_args(
        "tar",
        [
            "-C",
            conf.workspace_path().as_str(),
            "-xvf",
            test_data_src_path.as_str(),
        ],
    )
    .run()?;

    Ok(())
}

/// Download `gs_path` using gsutil. If `expected_hash` is provided,
/// check that it matches the SHA-256 of the downlodaed file. Unpack the
/// tarball and move chromiumos_test_image.bin to workspace/disk.bin.
fn download_and_extract_disk_image(
    conf: &Config,
    gs_resource: GsResource,
    expected_hash: Option<&str>,
) -> Result<()> {
    // Download the compressed test image to a temporary directory.
    let tmp_dir = TempDir::new_in(conf.workspace_path())?;
    let tmp_path = Utf8Path::from_path(tmp_dir.path()).unwrap();
    let download_path = tmp_path.join("chromiumos_test_image.tar.xz");
    gs_resource.download_to_file(&download_path)?;

    if let Some(expected_hash) = expected_hash {
        check_sha256_hash(&download_path, expected_hash)?;
    }

    // Extract the image.
    Command::with_args(
        "tar",
        [
            "xf",
            download_path.as_str(),
            // Change directory to the temporary directory.
            "-C",
            tmp_path.as_str(),
        ],
    )
    .run()?;

    // Move the image to the workspace.
    Command::with_args(
        "mv",
        [
            &tmp_path.join("chromiumos_test_image.bin"),
            conf.disk_path(),
        ],
    )
    .run()?;

    Ok(())
}

/// Find the latest ToT build of reven-private and download it. Requires
/// internal Google credentials.
fn download_latest_reven(conf: &Config) -> Result<()> {
    let board_dir = "reven-release";

    // Find the latest version using the LATEST-main file, which
    // contains a string like "R114-15410.0.0".
    let latest_main_resource = GsResource::new(
        CHROMEOS_IMAGE_ARCHIVE_BUCKET,
        format!("{board_dir}/LATEST-main"),
    );
    let latest_version = latest_main_resource.download_to_string()?;

    let test_image_resource = GsResource::new(
        CHROMEOS_IMAGE_ARCHIVE_BUCKET,
        format!("{board_dir}/{latest_version}/chromiumos_test_image.tar.xz"),
    );
    download_and_extract_disk_image(conf, test_image_resource, None)
}

/// Download a pinned build of the public reven board.
fn download_pinned_public_reven(conf: &Config) -> Result<()> {
    let hash = "d3ef6564c8716218441ca956139878928c0f368a326d5b5be0df6ad2184be66e";

    let test_image_resource = GsResource::new_public(
        CHROMEOS_LOCALMIRROR_BUCKET,
        format!("distfiles/reven-public-test-image-{}.tar.xz", &hash[..8]),
    );
    download_and_extract_disk_image(conf, test_image_resource, Some(hash))
}

/// Build futility, the firmware utility executable that is part of
/// vboot_reference.
fn build_futility(conf: &Config) -> Result<()> {
    let mut cmd = Command::with_args(
        "make",
        [
            "-C",
            conf.vboot_reference_path().as_str(),
            // Use clang since vboot sets args that gcc doesn't support.
            "CC=clang",
            "USE_FLASHROM=0",
            conf.futility_executable_path().as_str(),
        ],
    );
    let cflags = [
        // For compatiblity with openssl3, allow use of deprecated
        // functions.
        "-Wno-deprecated-declarations",
        // Disable this error to match the default chromeos build
        // flags. See b/231987783.
        "-Wno-int-conversion",
    ];

    cmd.env.insert("CFLAGS".into(), cflags.join(" ").into());
    cmd.run()?;

    Ok(())
}

fn generate_secure_boot_keys(conf: &Config) -> Result<()> {
    // Generate an RSA key for signing the first-stage bootloader. The
    // public half will be enrolled in the firmware.
    secure_boot::generate_rsa_key(&conf.secure_boot_root_key_paths(), "SecureBootRootTestKey")?;

    // Prepare both RSA and Ed25519 keys for signing the second-stage
    // bootloader. The RSA key is used when booting from shim, and the
    // Ed25519 is used when booting from crdyshim.
    secure_boot::generate_rsa_key(&conf.secure_boot_shim_key_paths(), "SecureBootShimTestKey")?;
    secure_boot::prepare_ed25519_key(conf)?;

    let root_key_paths = conf.secure_boot_root_key_paths();
    // Generate the PK/KEK and db vars for use with the enroller.
    secure_boot::generate_signed_vars(&root_key_paths, "PK")?;
    secure_boot::generate_signed_vars(&root_key_paths, "db")
}

/// Run the enroller in a VM to set up UEFI variables for secure boot.
fn enroll_secure_boot_keys(conf: &Config, action: &SetupAction) -> Result<()> {
    for arch in Arch::all() {
        // TODO(b/330536482): Skip 32-bit for now; the ia32 OVMF
        // firmware is broken.
        if arch == Arch::Ia32 {
            continue;
        }

        // TODO(b/403257806): Skip ARM for now. We don't currently run
        // ARM VM tests.
        if arch == Arch::Aarch64 {
            continue;
        }

        let ovmf = conf.ovmf_paths(arch);

        // Get the system path of the OVMF files installed via apt.
        let system_ovmf_dir = Utf8Path::new("/usr/share/OVMF/");
        let (system_code, system_vars) = match arch {
            Arch::Aarch64 => unimplemented!(),
            Arch::Ia32 => ("OVMF32_CODE_4M.secboot.fd", "OVMF32_VARS_4M.fd"),
            Arch::X64 => ("OVMF_CODE_4M.secboot.fd", "OVMF_VARS_4M.fd"),
        };
        let system_code = system_ovmf_dir.join(system_code);
        let system_vars = system_ovmf_dir.join(system_vars);

        let (args_code, args_vars) = match arch {
            Arch::Aarch64 => unimplemented!(),
            Arch::Ia32 => (action.ovmf32_code.as_ref(), action.ovmf32_vars.as_ref()),
            Arch::X64 => (action.ovmf64_code.as_ref(), action.ovmf64_vars.as_ref()),
        };

        // Copy the OVMF files to a local directory.
        let src_code_path = args_code.unwrap_or(&system_code);
        let src_vars_path = args_vars.unwrap_or(&system_vars);
        copy_file(src_code_path, ovmf.code())?;
        copy_file(src_vars_path, ovmf.original_vars())?;

        // Keep a copy of the original vars for running QEMU in
        // non-secure-boot mode.
        copy_file(ovmf.original_vars(), ovmf.secure_boot_vars())?;

        // Run the enroller in QEMU to set up secure boot UEFI variables.
        let qemu = QemuOpts {
            capture_output: false,
            display: Display::None,
            image_path: conf.enroller_disk_path(),
            ovmf,
            secure_boot: true,
            snapshot: false,
            timeout: None,
            tpm_version: None,
            network: false,
        };
        qemu.run_disk_image(conf)?;
    }

    Ok(())
}

fn run_prep_disk(conf: &Config) -> Result<()> {
    // Sign both kernel partitions.
    gen_disk::sign_kernel_partition(conf, "KERN-A")?;
    gen_disk::sign_kernel_partition(conf, "KERN-B")
}

/// Run various setup operations. This must be run once before running
/// any other xtask commands.
pub(super) fn run_setup(conf: &Config, action: &SetupAction) -> Result<()> {
    init_repos(conf)?;

    download_and_unpack_test_data(conf)?;

    // If the user has provided their own disk image on the command
    // line, use that.
    if let Some(disk_image) = &action.disk_image {
        copy_file(disk_image, conf.disk_path())?;
    }

    // If we don't have a disk image, download one from GS.
    if !conf.disk_path().exists() {
        if action.reven_private {
            download_latest_reven(conf)?;
        } else {
            download_pinned_public_reven(conf)?;
        }
    }

    build_futility(conf)?;

    generate_secure_boot_keys(conf)?;
    run_build_enroller(conf)?;
    enroll_secure_boot_keys(conf, action)?;

    // Build and install shim, and sign the kernel partitions with a
    // local key.
    run_prep_disk(conf)?;

    // Create disk image for testing flexor.
    gen_disk::gen_flexor_disk_image(conf)?;

    // Record that the latest version of the setup has succeeded.
    conf.write_setup_version(SETUP_VERSION)
}

pub(super) fn rerun_setup_if_needed(action: &Action, conf: &Config) -> Result<()> {
    // Don't run setup if the user is already doing it.
    if matches!(action, Action::Setup(_)) {
        return Ok(());
    }

    // Don't try to run setup if the workspace doesn't exist yet.
    if !conf.workspace_path().exists() {
        return Ok(());
    }

    // Nothing to do if the version is already high enough.
    let existing_version = conf.read_setup_version();
    if existing_version >= SETUP_VERSION {
        return Ok(());
    }

    println!("Re-running setup: upgrading from {existing_version} to {SETUP_VERSION}");

    // Put any version-specific cleanup operations here.

    // End version-specific cleanup operations.

    run_setup(conf, &SetupAction::default())
}
