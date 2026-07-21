#include "ble.h"
#include "config.h"

#if ENABLE_BLE_SCAN

#include "surveillance.h"
#include <NimBLEDevice.h>

// NimBLE-Arduino 1.4.x callback API. (Pinned in platformio.ini; the 2.x API
// renamed this class, so keep the dependency on the 1.4 series.)
class ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* dev) override {
    const uint8_t* payload = dev->getPayload();
    size_t len = dev->getPayloadLength();
    if (!payload || len == 0) return;
    surveillance_ble_adv(dev->getAddress().toString().c_str(),
                         (int8_t)dev->getRSSI(),
                         payload, (uint8_t)(len > 255 ? 255 : len));
  }
};

static NimBLEScan* s_scan = nullptr;

void ble_start() {
  NimBLEDevice::init("");
  // Passive scan: never transmit scan requests. Stealthier and lower power —
  // we only listen, matching the spirit of the Wi-Fi side.
  s_scan = NimBLEDevice::getScan();
  s_scan->setAdvertisedDeviceCallbacks(new ScanCallbacks(), /*wantDuplicates=*/true);
  s_scan->setActiveScan(false);
  s_scan->setInterval(BLE_SCAN_INTERVAL);
  s_scan->setWindow(BLE_SCAN_WINDOW);
  s_scan->setMaxResults(0);            // report via callback only, don't buffer
  s_scan->start(0, nullptr, false);    // scan forever
}

void ble_service() {
  if (s_scan && !s_scan->isScanning()) {
    s_scan->start(0, nullptr, false);
  }
}

#else  // ENABLE_BLE_SCAN

void ble_start()   {}
void ble_service() {}

#endif
