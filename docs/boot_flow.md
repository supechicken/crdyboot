# Boot flow

This document describes the steps that occur during the boot process,
from launching crdyboot up through running the kernel.

The first thing that needs to happen is loading, verifying, and running
crdyboot itself. This is handled by the firmware if crdyboot is run as
the first-stage bootloader, or handled by an early bootloader such as
[shim]. Crdyboot is signed with [sbsigntools] in the usual way for a
UEFI executable.

The following sections describe (in order) what crdyboot does.

## Self-revocation check

The first thing crdyboot does is a self-revocation check. This works by
checking a [UEFI variable] containing a numeric level against a level
embedded in the executable. If the embedded level is lower than the
value in the UEFI variable, crdyboot considers itself revoked and will
refuse to boot. Crdyboot also handles initializing and updating the
variable as needed. The variable is only accessible while boot services
are active, so this forms a security boundary.

The self-revocation check is very similar to [SBAT], and has the same
motivation: allow revocation without a perpetually-expanding dbx. The
dbx is Secure Boot's built-in revocation storage, which stores either
hashes or certificates to revoke. That requires more space to store than
component revocation, which is a problem given the space constraints of
UEFI's NVRAM.

See [`crdyboot/src/revocation.rs`][revocation.rs] for details of the
implementation.

## Load the embedded public key

In order to verify the data on the kernel partitions, crdyboot has an
embedded public key. This is similar to the embedded public key in
[shim], but stored differently. Crdyboot stores its key in a separate
section in the executable called `.vbpubk`. Storing it in its own
section makes it easy to update with `objcopy --update-section`. This
allows us to build in a test key by default, then easily switch to the
production key in signed images.

To load the key at runtime, crdyboot first uses the [`LoadedImage`] UEFI
protocol to get the executable's memory. Then it uses the [`object`]
crate to parse the PE header and get the `.vbpubk` section data.

See [`crdyboot/src/vbpubk.rs`][vbpubk.rs] for details of the implementation.

## Load and verify the kernel

Crdyboot uses the [vboot] firmware library (written in C) to load and
verify the kernel. That library searches the [GPT] for partitions with a
particular GUID indicating they contain ChromeOS kernel data. The
[kernel partition format] combines the kernel data with the command
line. This is a similar concept to [UKI] (Unified Kernel Image), but
predates it.

In order to perform disk IO operations, vboot requires the calling code
to provide certain callbacks. The actual disk operations are implemented
using the UEFI [`BlockIO`] protocol in [crdyboot/src/disk.rs][disk.rs].

Vboot uses partition attributes to determine which partition is
preferred, and verifies the signature of the contents against a public
key (see the previous section for where that key data comes from).

If successful, vboot returns the verified kernel data.

See [`vboot/src/load_kernel.rs`][load_kernel.rs] for the Rust code that
wraps vboot's C API.

## Measure the kernel into the TPM

Once the kernel data is loaded, we measure it into a TPM PCR. This means
we take a hash of the data (which includes both the executable and the
command-line args), and extend that into a PCR. The extend operation
looks like this: `PCR ← hash_function(PCR | new_hash)`. In other words,
we append the kernel-data hash to the existing value in the PCR, take
the hash of that, and store it to the PCR. See
[`libcrdy/src/tpm.rs`][tpm.rs].

## Set memory attributes for the kernel data

Before running the kernel we set NX memory attributes if the firmware
supports it. See the [NX] doc for details, and
[`libcrdy/src/nx.rs`][nx.rs] for the implementation.

## Run the kernel

Actually running the kernel is done with the help of the [EFI boot
stub]. That Linux feature makes the kernel itself act like a PE
executable, so we can call the entry point and transfer control that
way.

The method to get the entry point address depends on whether crdyboot is
32-bit or 64-bit. (Note that 32-bit crdyboot is still running on a
64-bit CPU and booting a 64-bit kernel, just the UEFI environment is
32-bit.) In both cases we use the [`object`] crate to parse the PE
header of the kernel (which is present thanks to the EFI boot stub). For
64-bit, the standard PE entry point is used. For 32-bit, the `.compat`
section contains additional entry points. We parse that data to get the
32-bit one.

See [`crdyboot/src/linux.rs`][linux.rs] for details of the implementation.

[EFI boot stub]: https://docs.kernel.org/admin-guide/efi-stub.html
[GPT]: https://en.wikipedia.org/wiki/GUID_Partition_Table
[NX]: nx.md
[SBAT]: https://github.com/rhboot/shim/blob/main/SBAT.md
[UEFI variable]: https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html#variable-services
[UKI]: https://github.com/uapi-group/specifications/blob/main/specs/unified_kernel_image.md
[`BlockIO`]: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#block-i-o-protocol
[`LoadedImage`]: https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html
[`object`]: https://crates.io/crates/object
[disk.rs]: ../crdyboot/src/disk.rs
[futility]: https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/refs/heads/main/futility/
[kernel partition format]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/disk_format.md#Kernel-partition-format
[linux.rs]: ../crdyboot/src/linux.rs
[load_kernel.rs]: ../vboot/src/load_kernel.rs
[nx.rs]: ../libcrdy/src/nx.rs
[vbpubk.rs]: ../crdyboot/src/vbpubk.rs
[revocation.rs]: ../crdyboot/src/revocation.rs
[sbsigntools]: https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git
[shim]: https://github.com/rhboot/shim
[tpm.rs]: ../libcrdy/src/tpm.rs
[vboot]: https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/refs/heads/main/firmware/
