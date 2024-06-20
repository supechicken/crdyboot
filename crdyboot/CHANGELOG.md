# Crdyboot Changelog

## 1.0.2
* Update to uefi-0.29. <https://crrev.com/c/5688491>
* firmware: Added firmware.rs, a module for installing firmware updates in
  tandem with the fwupd UEFI plugin. Initially only queries UEFI vars
  for updates and sets the status of any found
  updates. <https://crrev.com/c/5644131>

## 1.0.1

* Make TPM logs more detailed. <http://crrev.com/c/5440295>
* vboot: Build vboot with `UNROLL_LOOPS=1`. <http://crrev.com/c/5439795>
* vboot: Remove unused data from the kernel buffer. <http://crrev.com/c/5440301>
* vboot: Implement calloc. <http://crrev.com/c/5453715>
* Update to uefi-0.28 and drop uefi-services. <https://crrev.com/c/5582506>
