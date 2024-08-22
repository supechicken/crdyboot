# Crdyboot Changelog

## 1.0.2
* Update to uefi-0.29. <https://crrev.com/c/5688491>
* Relocate the kernel before booting it.
  <https://crrev.com/c/5625917>, <https://crrev.com/c/5625918>,
  <https://crrev.com/c/5625919>, <https://crrev.com/c/5625920>
* Add support for installing firmware capsule updates. This is currently
  gated behind the `firmware_update` feature
  flag.
  <https://crrev.com/c/5644131>, <https://crrev.com/c/5738677>,
  <https://crrev.com/c/5738678>, <https://crrev.com/c/5750485>,
  <https://crrev.com/c/5753432>, <https://crrev.com/c/5752265>,
  <https://crrev.com/c/5753433>, <https://crrev.com/c/5757599>,
  <https://crrev.com/c/5757600>, <https://crrev.com/c/5756148>,
  <https://crrev.com/c/5757605>, <https://crrev.com/c/5769666>,
  <https://crrev.com/c/5769667>, <https://crrev.com/c/5769768>,
  <https://crrev.com/c/5769664>, <https://crrev.com/c/5775369>,
  <https://crrev.com/c/5775370>, <https://crrev.com/c/5783171>,
  <https://crrev.com/c/5783172>, <https://crrev.com/c/5783167>,
  <https://crrev.com/c/5783331>, <https://crrev.com/c/5783332>,
  <https://crrev.com/c/5786425>, <https://crrev.com/c/5789152>,
  <https://crrev.com/c/5789153>, <https://crrev.com/c/5769665>,
  <https://crrev.com/c/5789156>, <https://crrev.com/c/5789157>,
  <https://crrev.com/c/5784171>

## 1.0.1

* Make TPM logs more detailed. <http://crrev.com/c/5440295>
* vboot: Build vboot with `UNROLL_LOOPS=1`. <http://crrev.com/c/5439795>
* vboot: Remove unused data from the kernel buffer. <http://crrev.com/c/5440301>
* vboot: Implement calloc. <http://crrev.com/c/5453715>
* Update to uefi-0.28 and drop uefi-services. <https://crrev.com/c/5582506>
