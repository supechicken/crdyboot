# Crdyboot Changelog

## 1.0.6

## 1.0.5
* Fix Flexor boot on several HP devices. <https://crrev.com/c/6298654>,
  <https://crrev.com/c/6292488>, <https://crrev.com/c/6479500>,
  <https://crrev.com/c/6665078>
* Create the `BootloaderSupportsFwupd` UEFI variable which tells `fwupd`
  that the bootloader can install capsule updates.
  <https://crrev.com/c/6344512>
* Add Aarch64 support. <https://crrev.com/c/6352300>
* Drop the `firmware_update` and `flexor` feature flags, these are
  always enabled now. <https://crrev.com/c/6360613>
* Avoid using the `PARTITION_INFO` protocol, as it's not supported on all
  devices. <https://crrev.com/c/6448617>

## 1.0.4
* Update to uefi-0.33. <https://crrev.com/c/6022537>
* Error handling improvements. <https://crrev.com/c/6004480>,
  <https://crrev.com/c/6011942>, <https://crrev.com/c/6011944>
* Enable Flexor. <https://crrev.com/c/5998837>,
  <https://crrev.com/c/6093628>, <https://crrev.com/c/6096549>
* When verbose logging is enabled, also enable verbose logging for
  Flexor. <https://crrev.com/c/6154248>,
  <https://crrev.com/c/6169099>
* Fix a Flexor boot failure on the HP
  Probook 445. <https://crrev.com/c/6178005>

## 1.0.3
* Update to uefi-0.31. <https://crrev.com/c/5808421>
* When verbose logging is enabled, copy SbatLevel to SbatLevelRT so that
  it can be viewed while the OS is running. <https://crrev.com/c/5802606>
* Add many new tests.
* Bug fixes and other improvements for the firmware update feature. It
  is still gated behind the `firmware_update` feature flag.
* Add initial support for launching flexor. This is gated behind the
  `flexor` feature flag.
  <https://crrev.com/c/5845690>, <https://crrev.com/c/5898632>,
  <https://crrev.com/c/5933487>
* Apply updated SBAT revocations if available.
  <https://crrev.com/c/5972838>, <https://crrev.com/c/5972839>,
  <https://crrev.com/c/5972840>

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
