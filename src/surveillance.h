// surveillance.h — Detects surveillance / tracking gear on Wi-Fi and BLE.
//
// Wi-Fi side: matches management-frame MACs against a vendor OUI table and
// SSIDs against a keyword list (cameras, DVRs, etc).
// BLE side:   matches advertisements against known tracker signatures
// (Apple Find My / AirTag, Tile, Samsung SmartTag).
#pragma once

#include <stdint.h>
#include <stddef.h>

void surveillance_init();

// Called for every 802.11 management frame. Extracts transmitter/BSSID and, for
// beacon/probe frames, the SSID, then runs OUI + keyword checks. Alerts are
// de-duplicated per device MAC.
void surveillance_wifi_frame(const uint8_t* frame, uint16_t len,
                             uint8_t subtype, int8_t rssi, uint8_t channel);

// Called for every BLE advertisement. `mac` is the printable address,
// `payload`/`len` the raw advertisement (AD structures). Alerts de-duplicated
// per address.
void surveillance_ble_adv(const char* mac, int8_t rssi,
                          const uint8_t* payload, uint8_t len);

// Count of BLE tracker signatures seen (for heartbeats).
uint32_t surveillance_ble_hits();

// Count of hacking / pentest devices seen (for heartbeats).
uint32_t surveillance_hacking_hits();
