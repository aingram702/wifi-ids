// Wi-Fi IDS Sensor — Seeed Studio XIAO ESP32-S3
//
// Passive 802.11 monitor that hops channels in promiscuous mode and raises
// alerts (JSON over USB serial + onboard LED) for:
//   * deauth / disassoc floods   -> denial-of-service, evil-twin setup
//   * evil twins                 -> a trusted SSID from an untrusted BSSID
//   * unknown SSIDs (optional)   -> any AP not on the trusted list
//   * surveillance devices       -> cameras (OUI/SSID) + BLE trackers
//
// Configure it in config.h. See README.md for wiring, flashing, and grid
// deployment.
#include <Arduino.h>

#include "config.h"
#include "alert.h"
#include "detector.h"
#include "sniffer.h"
#include "surveillance.h"
#include "ble.h"

static uint32_t s_last_heartbeat = 0;

void setup() {
  Serial.begin(115200);
  // Don't let a disconnected USB host stall a headless grid sensor: cap how
  // long a write can block, then drop instead of hanging the loop/callbacks.
  Serial.setTxTimeoutMs(20);
  delay(200);

  alert_init();  // must precede any alert_println()
  detector_init();
  surveillance_init();
  sniffer_start();
  ble_start();  // no-op unless ENABLE_BLE_SCAN

  char boot[128];
  snprintf(boot, sizeof(boot),
    "{\"sensor\":\"%s\",\"type\":\"boot\",\"msg\":\"wifi-ids sensor online\"}",
    SENSOR_ID);
  alert_println(boot);

  s_last_heartbeat = millis();
}

void loop() {
  sniffer_service();  // channel hopping
  ble_service();      // keep the BLE scan alive (no-op unless enabled)
  alert_service();    // LED blink housekeeping

  uint32_t now = millis();
  if ((uint32_t)(now - s_last_heartbeat) >= HEARTBEAT_MS) {
    s_last_heartbeat = now;
    char buf[256];
    detector_heartbeat_json(buf, sizeof(buf), sniffer_current_channel());
    alert_println(buf);
  }

  delay(1);  // yield to the Wi-Fi task
}
