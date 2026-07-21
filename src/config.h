// config.h — Sensor identity, detection thresholds, and the trusted-AP list.
//
// This is the only file most deployments need to touch. Give every board a
// unique SENSOR_ID, fill in kTrustedAps with the APs you actually own, then
// flash. Everything else has sane defaults.
#pragma once

#include <stdint.h>

// ---------------------------------------------------------------------------
// Sensor identity
// ---------------------------------------------------------------------------
// Stamped into every JSON alert line so a grid of sensors can be told apart.
#ifndef SENSOR_ID
#define SENSOR_ID "xiao-sensor-01"
#endif

// ---------------------------------------------------------------------------
// Channel hopping
// ---------------------------------------------------------------------------
// The radio can only listen to one channel at a time, so we hop. Trim this to
// {1, 6, 11} if you only care about the non-overlapping 2.4 GHz channels and
// want to dwell longer on each (better odds of catching a fast deauth burst).
// Note: channels 12-13 are not legal in some regions (e.g. US) — drop them if
// that applies to you.
static const uint8_t kChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

// How long to sit on each channel before hopping (milliseconds).
#define CHANNEL_DWELL_MS 300

// ---------------------------------------------------------------------------
// Deauthentication / disassociation flood detection
// ---------------------------------------------------------------------------
// Deauth frames are unauthenticated management frames — the classic Wi-Fi
// denial-of-service and the setup move for many evil-twin attacks. A handful
// per minute is normal; a burst is not.
#define DEAUTH_WINDOW_MS        1000  // sliding window length
#define DEAUTH_FLOOD_THRESHOLD  20    // deauth+disassoc frames per window -> alert

// ---------------------------------------------------------------------------
// Evil-twin / rogue-AP detection
// ---------------------------------------------------------------------------
// Map each SSID you trust to the BSSID(s) (AP MAC address) that are allowed to
// broadcast it. If a beacon advertises one of these SSIDs from any *other*
// BSSID, that's a possible evil twin and we alert. List one entry per AP; mesh
// networks and multi-AP setups just get several rows with the same SSID.
struct TrustedAp {
  const char* ssid;
  const char* bssid;  // lower-case, colon-separated: "aa:bb:cc:dd:ee:ff"
};

static const TrustedAp kTrustedAps[] = {
  // {"MyHomeWiFi", "aa:bb:cc:dd:ee:ff"},
  // {"MyHomeWiFi", "aa:bb:cc:dd:ee:00"},  // second AP, same SSID
};

// Alert the first time *any* SSID that is not in kTrustedAps is seen. This is
// noisy anywhere with neighbours — leave it off unless you're monitoring an
// isolated site where every new SSID is genuinely interesting.
#define ALERT_UNKNOWN_SSID 0

// ---------------------------------------------------------------------------
// Surveillance-device detection (cameras, trackers, spy gadgets)
// ---------------------------------------------------------------------------
// Wi-Fi side: match management-frame MACs against a vendor OUI table and SSIDs
// against a keyword list (see signatures.h — edit that file to add vendors,
// e.g. confirmed Flock/Axon OUIs). Fires once per device.
#define ENABLE_SURVEILLANCE_WIFI 1

// BLE side: scan for Bluetooth trackers (Apple Find My / AirTag, Tile, Samsung
// SmartTag). Uses the ESP32-S3's Bluetooth radio alongside Wi-Fi. Requires the
// NimBLE-Arduino library (auto-installed by PlatformIO). Set to 0 for a
// Wi-Fi-only build that doesn't need NimBLE.
#define ENABLE_BLE_SCAN 1

// BLE scan timing in 0.625 ms units. Window <= Interval; here ~50% duty so the
// shared radio still has time for Wi-Fi. (80 * 0.625 = 50 ms.)
#define BLE_SCAN_INTERVAL 160
#define BLE_SCAN_WINDOW   80

// ---------------------------------------------------------------------------
// Alerting
// ---------------------------------------------------------------------------
#define ALERT_LED_ENABLED  1     // blink the onboard LED on every alert
#define HEARTBEAT_MS       10000 // emit a status/heartbeat JSON line this often
