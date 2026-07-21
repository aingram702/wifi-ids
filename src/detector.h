// detector.h — The detection engine. Fed raw management frames, emits alerts.
#pragma once

#include <stdint.h>
#include <stddef.h>

// Reset internal state. Call once from setup().
void detector_init();

// Feed one received 802.11 frame. `frame`/`len` are the raw frame bytes,
// `rssi` the signal strength, `channel` where it was heard. Safe to call from
// the Wi-Fi promiscuous callback.
void detector_handle(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel);

// Fill `buf` with a heartbeat JSON line summarising counters since boot.
void detector_heartbeat_json(char* buf, size_t buf_len, uint8_t channel);
