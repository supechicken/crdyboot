# NX compatibility

[NX] means "no execute". A region of memory can be marked as no-execute, and
the processor will then refuse to run code from that region. This can be used
to improve security by maintaining a strict separation between memory that is
writable and memory that is executable. See [W^X] for details.

As of November 2022, [Microsoft requires NX compatibility][nx-req] for all UEFI
signing submissions. The specific requirements are:
1. PE sections must be page aligned (4KiB). This alignment requirement is only
   for the start of the section, not its end.
2. Each PE section can be either writable or executable, but not both.
3. The PE attribute `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` must be set.
4. Page zero cannot be used.
5. Stack space cannot be executable.
6. When loading another executable, a bootloader must enforce similar
   requirements on the child:
   1. Sections must be page aligned as described above.
   2. Each PE section can be either writable or executable, but not both.
   3. The PE attribute `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` must be set.
   4. If [`EFI_MEMORY_ATTRIBUTE_PROTOCOL`] is available, it must be used to
      enforce W^X on the child's sections.

Most of the requirements are trivially satisfied by crdyboot (and
crdyshim); the executable produced by rustc already covers the first
five requirements.

The final requirement, for enforcing NX compatibility in a child
executable, is handled in [`libcrdy/src/nx.rs`]. However, we only
enforce NX in the child if the [`EFI_MEMORY_ATTRIBUTE_PROTOCOL`] is
available. This is important, because our Linux kernel does not yet
support NX in its [EFI boot stub][stub]. As long as crdyboot is
executing on firmware that doesn't support the memory-attribute
protocol, this is fine; we won't stop the kernel from booting. By the
time we need to boot on devices with firmware that have support for the
memory-attribute protocol, we expect our kernel will properly support
NX.

[stub]: https://docs.kernel.org/admin-guide/efi-stub.html
[NX]: https://en.wikipedia.org/wiki/NX_bit
[W^X]: https://en.wikipedia.org/wiki/W%5EX
[`EFI_MEMORY_ATTRIBUTE_PROTOCOL`]: https://uefi.org/specs/UEFI/2.10/37_Secure_Technologies.html#memory-protection
[`libcrdy/src/nx.rs`]: ../libcrdy/src/nx.rs
[nx-req]: https://techcommunity.microsoft.com/t5/hardware-dev-center/new-uefi-ca-memory-mitigation-requirements-for-signing/ba-p/3608714
