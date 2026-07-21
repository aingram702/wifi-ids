// ieee80211.h — Minimal 802.11 frame layout helpers used by the detector.
//
// We only ever look at management frames (beacons, probe responses, deauth,
// disassoc), so this covers just the fixed MAC header and the fields we parse.
#pragma once

#include <stdint.h>

// Frame Control field lives in the first two bytes of every 802.11 frame.
// Byte 0 packs: protocol version (bits 0-1), type (bits 2-3), subtype (4-7).
static inline uint8_t wifi_frame_type(const uint8_t* frame)    { return (frame[0] >> 2) & 0x03; }
static inline uint8_t wifi_frame_subtype(const uint8_t* frame) { return (frame[0] >> 4) & 0x0F; }

// Frame types
#define WIFI_TYPE_MGMT 0x0

// Management-frame subtypes we care about
#define WIFI_SUBTYPE_ASSOC_REQ  0x0
#define WIFI_SUBTYPE_PROBE_RESP 0x5
#define WIFI_SUBTYPE_BEACON     0x8
#define WIFI_SUBTYPE_DISASSOC   0xA
#define WIFI_SUBTYPE_DEAUTH     0xC

// 802.11 management header is 24 bytes:
//   fc(2) duration(2) addr1(6) addr2(6) addr3(6) seq(2)
// addr1 = destination/receiver, addr2 = source/transmitter, addr3 = BSSID.
#define WIFI_MGMT_HDR_LEN 24
static inline const uint8_t* wifi_addr1(const uint8_t* frame) { return frame + 4;  } // DA / RA
static inline const uint8_t* wifi_addr2(const uint8_t* frame) { return frame + 10; } // SA / TA
static inline const uint8_t* wifi_addr3(const uint8_t* frame) { return frame + 16; } // BSSID

// Format a 6-byte MAC into "aa:bb:cc:dd:ee:ff" (needs an 18-byte buffer).
static inline void wifi_mac_to_str(const uint8_t* mac, char* out) {
  static const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 6; i++) {
    out[i * 3]     = hex[mac[i] >> 4];
    out[i * 3 + 1] = hex[mac[i] & 0x0F];
    out[i * 3 + 2] = (i < 5) ? ':' : '\0';
  }
}

// Extract the SSID from a beacon/probe-response body into a NUL-terminated
// string (up to 32 chars + NUL, so ssid_out must hold 33 bytes). `body` points
// just past the 24-byte MAC header; `body_len` is what remains of the frame.
//
// Body layout: timestamp(8) interval(2) capability(2) then tagged parameters
// as (tag, len, value...). The SSID is tag 0. Returns true on success.
static inline bool wifi_parse_ssid(const uint8_t* body, int body_len, char* ssid_out) {
  int pos = 12;  // skip the 12 bytes of fixed parameters
  while (pos + 2 <= body_len) {
    uint8_t tag = body[pos];
    uint8_t len = body[pos + 1];
    if (pos + 2 + len > body_len) break;
    if (tag == 0) {  // SSID element
      int n = len > 32 ? 32 : len;
      for (int i = 0; i < n; i++) {
        uint8_t c = body[pos + 2 + i];
        // Keep it printable so a crafted SSID can't corrupt the JSON output.
        ssid_out[i] = (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') ? c : '?';
      }
      ssid_out[n] = '\0';
      return true;
    }
    pos += 2 + len;
  }
  return false;
}
