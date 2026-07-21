// signatures.h — Fingerprints for surveillance / tracking devices.
//
// Three tables, all deliberately data-driven so you can extend them without
// touching detection code:
//
//   kOuiTable       Wi-Fi MAC prefixes (OUIs) of camera / surveillance vendors
//   kSsidKeywords   substrings in a broadcast/probed SSID that give a device away
//   (BLE signatures are matched in surveillance.cpp — see the notes there)
//
// PROVENANCE / ACCURACY: OUIs are IEEE-assigned per *vendor*, and vendors buy
// many blocks over time, so this is a curated seed list, not an exhaustive or
// authoritative one. A hit means "a device from this vendor is nearby," not
// "this exact model is a camera." Verify locally and extend — community
// projects (e.g. DeFlock) and `curl https://standards-oui.ieee.org/oui/oui.txt`
// are good sources. False positives are expected; treat hits as leads.
#pragma once

#include <stdint.h>

struct OuiEntry {
  uint8_t     p[3];       // first three bytes of the MAC (the OUI)
  const char* vendor;
  const char* category;   // camera | tracker | surveillance | networking
};

// Curated seed list. Uppercase hex, but compared numerically so case is moot.
static const OuiEntry kOuiTable[] = {
  // --- Hikvision (IP cameras, very widely deployed incl. rebrands) ---
  {{0x44, 0x19, 0xB6}, "Hikvision", "camera"},
  {{0x4C, 0xBD, 0x8F}, "Hikvision", "camera"},
  {{0x58, 0x03, 0xFB}, "Hikvision", "camera"},
  {{0xC0, 0x56, 0xE3}, "Hikvision", "camera"},
  {{0xBC, 0xAD, 0x28}, "Hikvision", "camera"},
  {{0x28, 0x57, 0xBE}, "Hikvision", "camera"},
  {{0x54, 0xC4, 0x15}, "Hikvision", "camera"},
  {{0xA4, 0x14, 0x37}, "Hikvision", "camera"},
  // --- Dahua (IP cameras; also OEMs Amcrest, Lorex, etc.) ---
  {{0x3C, 0xEF, 0x8C}, "Dahua", "camera"},
  {{0x90, 0x02, 0xA9}, "Dahua", "camera"},
  {{0x14, 0xA7, 0x8B}, "Dahua", "camera"},
  {{0x08, 0xED, 0xED}, "Dahua", "camera"},
  {{0xE0, 0x50, 0x8B}, "Dahua", "camera"},
  {{0x24, 0x52, 0x6A}, "Dahua", "camera"},
  // --- Axis Communications (network cameras) ---
  {{0x00, 0x40, 0x8C}, "Axis", "camera"},
  {{0xAC, 0xCC, 0x8E}, "Axis", "camera"},
  {{0xB8, 0xA4, 0x4F}, "Axis", "camera"},
  {{0xE8, 0x27, 0x25}, "Axis", "camera"},
  // --- Ubiquiti (UniFi Protect cameras + networking) ---
  {{0x00, 0x15, 0x6D}, "Ubiquiti", "networking"},
  {{0x04, 0x18, 0xD6}, "Ubiquiti", "networking"},
  {{0x24, 0x5A, 0x4C}, "Ubiquiti", "networking"},
  {{0x74, 0xAC, 0xB9}, "Ubiquiti", "networking"},
  {{0x78, 0x8A, 0x20}, "Ubiquiti", "networking"},
  {{0xB4, 0xFB, 0xE4}, "Ubiquiti", "networking"},
  {{0xDC, 0x9F, 0xDB}, "Ubiquiti", "networking"},
  {{0xFC, 0xEC, 0xDA}, "Ubiquiti", "networking"},
  {{0x68, 0xD7, 0x9A}, "Ubiquiti", "networking"},
  // --- Amazon (Ring / Blink doorbells & cameras, Echo) ---
  {{0x00, 0x71, 0x47}, "Amazon", "camera"},
  {{0x0C, 0x47, 0xC9}, "Amazon", "camera"},
  {{0x34, 0xD2, 0x70}, "Amazon", "camera"},
  {{0x44, 0x65, 0x0D}, "Amazon", "camera"},
  {{0x68, 0x37, 0xE9}, "Amazon", "camera"},
  {{0x74, 0xC2, 0x46}, "Amazon", "camera"},
  {{0xF0, 0x81, 0x73}, "Amazon", "camera"},
  {{0xFC, 0x65, 0xDE}, "Amazon", "camera"},
  {{0x88, 0x71, 0xE5}, "Amazon", "camera"},
  {{0x50, 0xDC, 0xE7}, "Amazon", "camera"},
  // --- Google / Nest (Nest Cam, Doorbell) ---
  {{0x18, 0xB4, 0x30}, "Nest", "camera"},
  {{0x64, 0x16, 0x66}, "Nest", "camera"},
  {{0x00, 0x1A, 0x11}, "Google", "camera"},
  {{0x3C, 0x5A, 0xB4}, "Google", "camera"},
  {{0x94, 0xEB, 0x2C}, "Google", "camera"},
  {{0xA4, 0x77, 0x33}, "Google", "camera"},
  {{0xF4, 0xF5, 0xD8}, "Google", "camera"},
  {{0xF4, 0xF5, 0xE8}, "Google", "camera"},
  {{0xD8, 0x6C, 0x63}, "Google", "camera"},
  {{0x54, 0x60, 0x09}, "Google", "camera"},
};

struct SsidKeyword {
  const char* kw;         // lower-case substring, matched case-insensitively
  const char* vendor;
  const char* category;
};

// SSIDs that a device broadcasts (setup/AP mode) or actively probes for. Kept
// distinctive on purpose to limit false positives — bare words like "cam" or
// "ring" match too much English, so they're intentionally absent. Flock's
// cameras are LTE-first and don't reliably beacon, but their maintenance/
// provisioning Wi-Fi and probe traffic can carry the name, so we watch for it.
static const SsidKeyword kSsidKeywords[] = {
  {"flock",     "Flock Safety",  "surveillance"},
  {"axon",      "Axon",          "surveillance"},   // body/fleet cameras
  {"reolink",   "Reolink",       "camera"},
  {"hikvision", "Hikvision",     "camera"},
  {"dahua",     "Dahua",         "camera"},
  {"amcrest",   "Amcrest",       "camera"},
  {"lorex",     "Lorex",         "camera"},
  {"wyzecam",   "Wyze",          "camera"},
  {"wyze",      "Wyze",          "camera"},
  {"arlo",      "Arlo",          "camera"},
  {"ipcam",     "Generic IPCam", "camera"},
  {"ring-",     "Ring",          "camera"},
  {"blink-",    "Blink",         "camera"},
  {"unifi",     "Ubiquiti",      "networking"},
  {"ubnt",      "Ubiquiti",      "networking"},
};

// --- Lookups ---------------------------------------------------------------

// Locally-administered bit: set on randomized/software MACs, whose OUI is
// meaningless. Skip OUI matching on those.
static inline bool mac_is_local(const uint8_t* mac)     { return (mac[0] & 0x02) != 0; }
static inline bool mac_is_multicast(const uint8_t* mac) { return (mac[0] & 0x01) != 0; }

static inline const OuiEntry* oui_lookup(const uint8_t* mac) {
  if (mac_is_local(mac) || mac_is_multicast(mac)) return nullptr;
  for (unsigned i = 0; i < sizeof(kOuiTable) / sizeof(kOuiTable[0]); i++) {
    if (mac[0] == kOuiTable[i].p[0] &&
        mac[1] == kOuiTable[i].p[1] &&
        mac[2] == kOuiTable[i].p[2]) {
      return &kOuiTable[i];
    }
  }
  return nullptr;
}

// Case-insensitive substring search (strcasestr isn't portable across cores).
static inline const SsidKeyword* ssid_keyword_match(const char* ssid) {
  for (unsigned i = 0; i < sizeof(kSsidKeywords) / sizeof(kSsidKeywords[0]); i++) {
    const char* needle = kSsidKeywords[i].kw;
    for (const char* h = ssid; *h; h++) {
      const char* a = h;
      const char* b = needle;
      while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) break;
        a++; b++;
      }
      if (!*b) return &kSsidKeywords[i];  // reached end of needle -> matched
    }
  }
  return nullptr;
}
