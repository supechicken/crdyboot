# Test Data

Some tests use test data that's downloaded from a GS
bucket. Occasionally that test data may need to be refreshed. The steps
to do that are documented here.

## Generating and uploading the test data

```console
# Delete the full disk image, if present.
rm workspace/disk.bin

# Download a fresh disk image from GE (among other things).
cargo xtask setup --reven-private

# Generate the test data tarball in the repo root directory.
# The file will be named like this: `crdyboot_test_data_<XXXXXX>.tar.xz`.
cargo xtask gen-test-data-tarball

# Check what updates to the test are needed.
tar xvf crdyboot_test_data_<XXXXXX>.tar.xz -C workspace
cargo xtask check
```

The tests will need to be updated to match the kernel command line in
the test data. Since the command line includes the rootfs hash and salt,
which are unique to every image, every update to the test data will
require at least one update to the tests. The changes should be in the
same CL where the test data URL is updated (as described later).

Now upload the file to GS with public read permissions (based on the
instructions in [ChromiumOS Archive Mirrors]):

```console
# Fill in `<XXXXXX>` from the actual name of the tarball.
gsutil cp -n -a public-read crdyboot_test_data_<XXXXXX>.tar.xz gs://chromeos-localmirror/distfiles/
```

At this point a new file has been uploaded, but that won't affect the
tests outside of your local environment yet. That requires changing the
test data URL, as described in the next section.

## Changing the test data URL

After uploading a new test data tarball, there are two source
modifications needed to actually switch over to the new tarball.

First, get the SHA-256 hash of the tarball:

```console
# Fill in `<XXXXXX>` from the actual name of the tarball.
sha256sum crdyboot_test_data_<XXXXXX>.tar.xz
```

In [`xtask/src/config.rs`](../xtask/src/config.rs), update the
`TEST_DATA_HASH` constant to the new hash.

In [`crdyboot-9999.ebuild`], update the truncated hash in `SRC_URI` to
the new hash. Then update the package manifest:

```console
# Run this in the chroot:
ebuild ../third_party/chromiumos-overlay/sys-boot/crdyboot/crdyboot-9999.ebuild manifest
```

Any changes that were needed to the test code to work with the new test
tarball should go in the same CL that updates `TEST_DATA_HASH`. Make
sure to `Cq-Depend` the crdyboot and chromiumos-overlay CLs.

Example CLs: [crdyboot CL], [chromiumos-overlay CL]

[ChromiumOS Archive Mirrors]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#updating-localmirror-localmirror_private-getting-files-onto-localmirror-command-line-interface
[`crdyboot-9999.ebuild`]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/sys-boot/crdyboot/crdyboot-9999.ebuild
[crdyboot CL]: https://chromium-review.googlesource.com/c/chromiumos/platform/crdyboot/+/4855545
[chromiumos-overlay CL]: https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/4853856
