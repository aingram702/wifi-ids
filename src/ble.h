// ble.h — BLE scanner that feeds advertisements to the surveillance detector.
//
// Compiled out entirely unless ENABLE_BLE_SCAN is set (see config.h), so a
// Wi-Fi-only build doesn't need the NimBLE library. When enabled, it runs a
// continuous passive scan alongside Wi-Fi promiscuous mode; the radio is shared
// via the ESP32 Wi-Fi/BT coexistence framework.
#pragma once

// Start continuous BLE scanning. No-op if BLE is disabled at compile time.
void ble_start();

// Housekeeping (restarts the scan if the stack ever stops it). Call from loop().
void ble_service();
