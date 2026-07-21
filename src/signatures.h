// signatures.h — Fingerprints for surveillance / recording devices.
//
// Three tables, all deliberately data-driven so you can extend them without
// touching detection code:
//
//   kOuiTable       Wi-Fi MAC prefixes (OUIs) of camera / surveillance vendors
//   kSsidKeywords   substrings in a broadcast/probed SSID that give a device away
//   (BLE tracker signatures are matched in surveillance.cpp — see notes there)
//
// SCOPE: intentionally limited to *surveillance and recording* gear — fixed and
// PTZ cameras, video doorbells, NVR/DVR ecosystems, body/fleet/ALPR cameras,
// action cams, camera drones, and Bluetooth item trackers. General-purpose
// networking, phones, and PCs are deliberately excluded to avoid false alarms.
//
// PROVENANCE / ACCURACY: OUIs are IEEE-assigned per *vendor*, and vendors buy
// many blocks over time, so this is a curated seed list, not an exhaustive or
// authoritative one. A hit means "a device from this vendor is nearby," not
// "this exact model is a camera." An OUI that turns out to be wrong simply never
// matches (it cannot cause a false positive for someone else's device). Verify
// locally and extend — `curl https://standards-oui.ieee.org/oui/oui.txt` and
// community projects (e.g. DeFlock) are good sources.
#pragma once

#include <stdint.h>

struct OuiEntry {
  uint8_t     p[3];       // first three bytes of the MAC (the OUI)
  const char* vendor;
  const char* category;   // camera | recording | drone | tracker | surveillance | networking
};

// Curated seed list. Uppercase hex, but compared numerically so case is moot.
// Only vendors whose blocks are camera/recording-specific are listed with a
// device category; blocks shared with speakers/streamers are avoided.
static const OuiEntry kOuiTable[] = {
  // --- Hikvision (IP cameras, NVRs; also OEMs many rebrands) ---
  {{0x44, 0x19, 0xB6}, "Hikvision", "camera"},
  {{0x4C, 0xBD, 0x8F}, "Hikvision", "camera"},
  {{0x58, 0x03, 0xFB}, "Hikvision", "camera"},
  {{0xC0, 0x56, 0xE3}, "Hikvision", "camera"},
  {{0xBC, 0xAD, 0x28}, "Hikvision", "camera"},
  {{0x28, 0x57, 0xBE}, "Hikvision", "camera"},
  {{0x54, 0xC4, 0x15}, "Hikvision", "camera"},
  {{0xA4, 0x14, 0x37}, "Hikvision", "camera"},
  {{0xC4, 0x2F, 0x90}, "Hikvision", "camera"},
  {{0xF8, 0x4D, 0xFC}, "Hikvision", "camera"},
  // --- Dahua (IP cameras; OEMs Amcrest, Lorex, and others) ---
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
  // --- Other dedicated IP-camera vendors (low false-positive risk) ---
  {{0x00, 0x02, 0xD1}, "Vivotek",   "camera"},
  {{0x00, 0x03, 0xC5}, "Mobotix",   "camera"},
  {{0x00, 0x13, 0xE2}, "GeoVision", "camera"},
  {{0x00, 0x0F, 0x7C}, "ACTi",      "camera"},
  {{0x2C, 0xAA, 0x8E}, "Wyze",      "camera"},
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
  // --- Amazon (Ring / Blink doorbells & cameras) ---
  // NOTE: these blocks are shared with Echo speakers/Fire devices, so a hit is
  // "an Amazon device," not necessarily a camera. Kept because Ring/Blink are
  // common surveillance gear; remove if the false positives bother you.
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
  // --- Google / Nest (Nest Cam, Doorbell) — blocks shared with Home speakers ---
  {{0x18, 0xB4, 0x30}, "Nest",   "camera"},
  {{0x64, 0x16, 0x66}, "Nest",   "camera"},
  {{0x00, 0x1A, 0x11}, "Google", "camera"},
  {{0x3C, 0x5A, 0xB4}, "Google", "camera"},
  {{0x94, 0xEB, 0x2C}, "Google", "camera"},
  {{0xA4, 0x77, 0x33}, "Google", "camera"},
  {{0xF4, 0xF5, 0xD8}, "Google", "camera"},
  {{0xF4, 0xF5, 0xE8}, "Google", "camera"},
  {{0xD8, 0x6C, 0x63}, "Google", "camera"},
  {{0x54, 0x60, 0x09}, "Google", "camera"},
  // --- Action cameras / camera drones (recording devices) ---
  {{0xD4, 0xD9, 0x19}, "GoPro", "recording"},
  {{0x60, 0x60, 0x1F}, "DJI",   "drone"},
};

struct SsidKeyword {
  const char* kw;         // lower-case substring, matched case-insensitively
  const char* vendor;
  const char* category;
};

// SSIDs a device broadcasts (setup/AP mode) or actively probes for. Kept
// distinctive on purpose to limit false positives — bare words like "cam" or
// "ring" match too much English, so they're intentionally absent. Flock's
// cameras are LTE-first and don't reliably beacon, but their maintenance/
// provisioning Wi-Fi and probe traffic can carry the name, so we watch for it.
static const SsidKeyword kSsidKeywords[] = {
  // Police / fleet / ALPR / body cameras
  {"flock",        "Flock Safety", "surveillance"},
  {"axon",         "Axon",         "surveillance"},
  {"vigilant",     "Vigilant",     "surveillance"},
  {"verkada",      "Verkada",      "surveillance"},
  {"avigilon",     "Avigilon",     "surveillance"},
  {"bodycam",      "Body camera",  "recording"},
  // Consumer / prosumer IP cameras & doorbells
  {"reolink",      "Reolink",      "camera"},
  {"hikvision",    "Hikvision",    "camera"},
  {"ezviz",        "EZVIZ",        "camera"},
  {"dahua",        "Dahua",        "camera"},
  {"amcrest",      "Amcrest",      "camera"},
  {"lorex",        "Lorex",        "camera"},
  {"swann",        "Swann",        "camera"},
  {"foscam",       "Foscam",       "camera"},
  {"uniview",      "Uniview",      "camera"},
  {"wisenet",      "Hanwha",       "camera"},
  {"hanwha",       "Hanwha",       "camera"},
  {"vivotek",      "Vivotek",      "camera"},
  {"wyzecam",      "Wyze",         "camera"},
  {"wyze",         "Wyze",         "camera"},
  {"arlo",         "Arlo",         "camera"},
  {"eufy",         "Eufy",         "camera"},
  {"tapo",         "TP-Link Tapo", "camera"},
  {"kasacam",      "TP-Link Kasa", "camera"},
  {"nestcam",      "Nest",         "camera"},
  {"vivint",       "Vivint",       "camera"},
  {"ring-",        "Ring",         "camera"},
  {"blink-",       "Blink",        "camera"},
  // Generic camera / CCTV giveaways
  {"ipcam",        "Generic IPCam","camera"},
  {"ipcamera",     "Generic IPCam","camera"},
  {"netcam",       "Generic IPCam","camera"},
  {"cctv",         "Generic CCTV", "camera"},
  {"doorbell",     "Video doorbell","camera"},
  {"spycam",       "Hidden camera","surveillance"},
  {"surveillance", "Surveillance", "surveillance"},
  // Action cameras / camera drones (recording)
  {"gopro",        "GoPro",        "recording"},
  {"insta360",     "Insta360",     "recording"},
  {"dji-",         "DJI",          "drone"},
  {"mavic",        "DJI",          "drone"},
  {"osmo",         "DJI",          "recording"},
  // Camera-capable networking gear
  {"unifi",        "Ubiquiti",     "networking"},
  {"ubnt",         "Ubiquiti",     "networking"},
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

// Case-insensitive substring test (strcasestr isn't portable across cores).
static inline bool ci_contains(const char* hay, const char* needle) {
  for (const char* h = hay; *h; h++) {
    const char* a = h;
    const char* b = needle;
    while (*a && *b) {
      char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
      char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
      if (ca != cb) break;
      a++; b++;
    }
    if (!*b) return true;  // reached end of needle -> matched
  }
  return false;
}

static inline const SsidKeyword* ssid_keyword_match(const char* ssid) {
  for (unsigned i = 0; i < sizeof(kSsidKeywords) / sizeof(kSsidKeywords[0]); i++)
    if (ci_contains(ssid, kSsidKeywords[i].kw)) return &kSsidKeywords[i];
  return nullptr;
}

// ---------------------------------------------------------------------------
// Hacking / pentest device fingerprints
// ---------------------------------------------------------------------------
// These use commodity radios (ESP32/Atheros/MediaTek/nRF), so there's no
// reliable vendor OUI — a Raspberry Pi or ESP32 OUI would flag every hobby
// project. Detection is therefore by the telltale names they broadcast:
// default AP SSIDs (Wi-Fi) and BLE local names. Extend freely.

struct HackSsid { const char* kw; const char* tool; };
static const HackSsid kHackingSsids[] = {
  {"pineapple",     "WiFi Pineapple"},        // Hak5
  {"wifipineapple", "WiFi Pineapple"},
  {"hak5",          "Hak5 device"},
  {"keycroc",       "Hak5 Key Croc"},
  {"bashbunny",     "Hak5 Bash Bunny"},
  {"lanturtle",     "Hak5 LAN Turtle"},
  {"sharkjack",     "Hak5 Shark Jack"},
  {"packetsquirrel","Hak5 Packet Squirrel"},
  {"o.mg",          "O.MG device"},           // O.MG cable/plug
  {"omg-",          "O.MG device"},
  {"pwnagotchi",    "Pwnagotchi"},
  {"pwned",         "WiFi Deauther"},          // ESP8266 Deauther default AP
  {"deauther",      "WiFi Deauther"},          // full word — won't hit "deauthorized"
  {"marauder",      "ESP32 Marauder"},
  {"esp32marauder", "ESP32 Marauder"},
  {"evilportal",    "Evil Portal"},            // Flipper/Marauder captive portal
  {"flipper",       "Flipper Zero"},           // Flipper Wi-Fi devboard AP
};

struct HackName { const char* kw; const char* tool; };
static const HackName kHackingBleNames[] = {
  {"flipper",       "Flipper Zero"},           // BLE local name "Flipper <name>"
};

static inline const HackSsid* hacking_ssid_match(const char* ssid) {
  for (unsigned i = 0; i < sizeof(kHackingSsids) / sizeof(kHackingSsids[0]); i++)
    if (ci_contains(ssid, kHackingSsids[i].kw)) return &kHackingSsids[i];
  return nullptr;
}
static inline const HackName* hacking_ble_name_match(const char* name) {
  for (unsigned i = 0; i < sizeof(kHackingBleNames) / sizeof(kHackingBleNames[0]); i++)
    if (ci_contains(name, kHackingBleNames[i].kw)) return &kHackingBleNames[i];
  return nullptr;
}
