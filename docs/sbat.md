# SBAT

All signed bootloader executables must contain SBAT (Secure Boot
Advanced Targeting) metadata for revocation purposes. The inclusion of
SBAT is not yet listed as one of Microsoft's [UEFI Signing Requirements],
but we expect they will want us to include SBAT data so that revocations
can occur without using up more `dbx` space. See shim's [`SBAT.md`] for
more background on why it's needed and details of the format.

## Updates

There are two fields in the bootloader component that we expect to
change over time: the generation number and the version number.

For example, here is the original crdyboot SBAT data:

```csv
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
crdyboot,1,Google,crdyboot,1.0.0,https://chromium.googlesource.com/chromiumos/platform/crdyboot
```

The second line contains the bootloader component. The second field
(`1`) is the generation number and the fifth field (`1.0.0`) is the
version number. Note that only the first two fields of each record are
machine-readable, everything after that is just for human consumption.

The generation number must be bumped any time a security fix
necessitates revoking older versions. In more detail:
1. A security flaw is discovered.
2. The fix is applied to the code.
3. The generation number is bumped.
4. The new version is rolled out.
5. Wait for the rollout to be sufficiently complete\* such that a
   revocation won't prevent people who still have the old bootloader
   from booting.
6. Update the SBAT revocation data to revoke all earlier generations of
   the component.
7. Roll out a new version of crdyshim that contains the updated
   revocations.

Note that the canonical source of revocation data is in
[`SbatLevel_Variable.txt`] in the shim repo. Revocations should be
submitted there as well as applied to [`sbat_revocations.csv`] in this
repo.

\* Exactly what constitutes a "sufficiently complete" rollout is not
   fully defined yet. We will need to consider scenarios such as OS
   rollbacks, switching from the dev channel to the stable channel,
   livebooting a newer installer, etc, and decide what the appropriate
   balance is between preventing bootloader rollback attacks and
   avoiding unexpected boot failures on end-user devices.

## Implementation

Each bootloader has its own CSV file that provides the metadata:
* [`crdyboot/sbat.csv`](../crdyboot/sbat.csv)
* [`crdyshim/sbat.csv`](../crdyshim/sbat.csv)

The metadata file is copied verbatim into a `.sbat` section of the final
executable. This is done via macro invocation that looks like this:

```rust
embed_section!(SBAT, ".sbat", "../sbat.csv");
```

The macro is defined in [`libcrdy/src/util.rs`]. It creates a static
variable and uses the [`link_section`] attribute to place it in the
appropriate section.

## Revocations

Both crdyshim and crdyboot contain the same embedded list of SBAT
revocations. See [`sbat_revocations.csv`]. That file can be updated with
`cargo xtask update-sbat-revocations`, which will pull updates from
[`SbatLevel_Variable.txt`] in the shim repo.

Shortly after launching, both crdyshim and crdyboot check if the UEFI
variable containing SBAT revocations needs to be updated by comparing
against the date in the embedded revocation list. If the UEFI variable
is out of date, the embedded revocations are copied to the variable.

[UEFI Signing Requirements]: https://techcommunity.microsoft.com/t5/hardware-dev-center/updated-uefi-signing-requirements/ba-p/1062916
[`SBAT.md`]: https://github.com/rhboot/shim/blob/HEAD/SBAT.md
[`libcrdy/src/util.rs`]: ../libcrdy/src/util.rs
[`link_section`]: https://doc.rust-lang.org/beta/reference/abi.html#the-link_section-attribute
[`sbat_revocations.csv`]: ../libcrdy/sbat_revocations.csv
[`SbatLevel_Variable.txt`]: https://github.com/rhboot/shim/blob/HEAD/SbatLevel_Variable.txt
