#include "surveillance.h"
#include "signatures.h"
#include "ieee80211.h"
#include "alert.h"
#include "config.h"

#include <Arduino.h>
#include <string.h>
#include <strings.h>  // strcasecmp

static uint32_t s_ble_hits = 0;
static uint32_t s_hacking_hits = 0;

// ---------------------------------------------------------------------------
// Ignore list — suppress alerts for the user's own known surveillance devices.
// ---------------------------------------------------------------------------
static bool surv_ignore_mac(const char* macstr) {
  for (unsigned i = 0; i < sizeof(kSurveillanceIgnoreMacs) / sizeof(kSurveillanceIgnoreMacs[0]); i++)
    if (strcasecmp(macstr, kSurveillanceIgnoreMacs[i]) == 0) return true;
  return false;
}
static bool surv_ignore_ssid(const char* ssid) {
  for (unsigned i = 0; i < sizeof(kSurveillanceIgnoreSsids) / sizeof(kSurveillanceIgnoreSsids[0]); i++)
    if (strcmp(ssid, kSurveillanceIgnoreSsids[i]) == 0) return true;
  return false;
}

// ---------------------------------------------------------------------------
// De-dup registries. Each only holds devices that have *already* alerted, so
// they stay small (they don't accumulate every device in range).
// ---------------------------------------------------------------------------
#define SEEN_OUI  0x1
#define SEEN_SSID 0x2
#define SEEN_HACK 0x4

struct WifiSeen { uint8_t mac[6]; uint8_t flags; bool used; };
#define WIFI_SEEN_MAX 128
static WifiSeen s_wifi_seen[WIFI_SEEN_MAX];

static WifiSeen* wifi_seen_get(const uint8_t* mac) {
  int free_slot = -1;
  for (int i = 0; i < WIFI_SEEN_MAX; i++) {
    if (s_wifi_seen[i].used) {
      if (memcmp(s_wifi_seen[i].mac, mac, 6) == 0) return &s_wifi_seen[i];
    } else if (free_slot < 0) {
      free_slot = i;
    }
  }
  if (free_slot < 0) return nullptr;
  WifiSeen* r = &s_wifi_seen[free_slot];
  memcpy(r->mac, mac, 6);
  r->flags = 0;
  r->used = true;
  return r;
}

// BLE addresses rotate (~15 min for Find My), so a ring buffer is ideal: a
// re-alert after rotation is a useful "still here" signal, not noise.
struct BleSeen { char mac[18]; bool used; };
#define BLE_SEEN_MAX 160
static BleSeen s_ble_seen[BLE_SEEN_MAX];
static int s_ble_next = 0;

static bool ble_already_alerted(const char* mac) {
  for (int i = 0; i < BLE_SEEN_MAX; i++)
    if (s_ble_seen[i].used && strcmp(s_ble_seen[i].mac, mac) == 0) return true;
  strncpy(s_ble_seen[s_ble_next].mac, mac, 17);
  s_ble_seen[s_ble_next].mac[17] = '\0';
  s_ble_seen[s_ble_next].used = true;
  s_ble_next = (s_ble_next + 1) % BLE_SEEN_MAX;
  return false;
}

// ---------------------------------------------------------------------------
void surveillance_init() {
  memset(s_wifi_seen, 0, sizeof(s_wifi_seen));
  memset(s_ble_seen, 0, sizeof(s_ble_seen));
  s_ble_next = 0;
  s_ble_hits = 0;
  s_hacking_hits = 0;
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------
static void emit_wifi_oui(const uint8_t* mac, const OuiEntry* e,
                          uint8_t channel, int8_t rssi) {
  char m[18];
  wifi_mac_to_str(mac, m);
  char buf[288];
  snprintf(buf, sizeof(buf),
    "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"surveillance_device\",\"radio\":\"wifi\","
    "\"match\":\"oui\",\"category\":\"%s\",\"vendor\":\"%s\",\"mac\":\"%s\","
    "\"channel\":%u,\"rssi\":%d}",
    SENSOR_ID, (unsigned long)millis(), e->category, e->vendor, m, channel, rssi);
  alert_event(buf);
}

static void emit_wifi_ssid(const uint8_t* mac, const char* ssid,
                           const SsidKeyword* k, uint8_t channel, int8_t rssi) {
  char m[18];
  wifi_mac_to_str(mac, m);
  char buf[352];
  snprintf(buf, sizeof(buf),
    "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"surveillance_device\",\"radio\":\"wifi\","
    "\"match\":\"ssid\",\"category\":\"%s\",\"vendor\":\"%s\",\"ssid\":\"%s\","
    "\"mac\":\"%s\",\"channel\":%u,\"rssi\":%d}",
    SENSOR_ID, (unsigned long)millis(), k->category, k->vendor, ssid, m, channel, rssi);
  alert_event(buf);
}

static void emit_hacking_wifi(const uint8_t* mac, const char* ssid,
                              const HackSsid* h, uint8_t channel, int8_t rssi) {
  char m[18];
  wifi_mac_to_str(mac, m);
  char buf[352];
  snprintf(buf, sizeof(buf),
    "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"hacking_device\",\"radio\":\"wifi\","
    "\"match\":\"ssid\",\"tool\":\"%s\",\"ssid\":\"%s\",\"mac\":\"%s\","
    "\"channel\":%u,\"rssi\":%d}",
    SENSOR_ID, (unsigned long)millis(), h->tool, ssid, m, channel, rssi);
  alert_event(buf);
}

static void check_oui(const uint8_t* mac, uint8_t channel, int8_t rssi) {
  const OuiEntry* e = oui_lookup(mac);
  if (!e) return;
  char m[18];
  wifi_mac_to_str(mac, m);
  if (surv_ignore_mac(m)) return;
  WifiSeen* s = wifi_seen_get(mac);
  if (s && !(s->flags & SEEN_OUI)) {
    s->flags |= SEEN_OUI;
    emit_wifi_oui(mac, e, channel, rssi);
  }
}

void surveillance_wifi_frame(const uint8_t* frame, uint16_t len,
                             uint8_t subtype, int8_t rssi, uint8_t channel) {
  if (len < WIFI_MGMT_HDR_LEN) return;
  const uint8_t* a2 = wifi_addr2(frame);  // transmitter (client or AP)
  const uint8_t* a3 = wifi_addr3(frame);  // BSSID

  // OUI check on the transmitter, and the BSSID if it's a different device.
  check_oui(a2, channel, rssi);
  if (memcmp(a2, a3, 6) != 0) check_oui(a3, channel, rssi);

  // SSID keyword check on frames that carry one.
  int fixed_len;
  switch (subtype) {
    case WIFI_SUBTYPE_BEACON:
    case WIFI_SUBTYPE_PROBE_RESP: fixed_len = 12; break;
    case WIFI_SUBTYPE_ASSOC_REQ:  fixed_len = 4;  break;  // capability(2)+listen(2)
    case 0x04 /* probe request */: fixed_len = 0;  break;
    default: return;
  }
  char ssid[33];
  if (!wifi_parse_ssid(frame + WIFI_MGMT_HDR_LEN, (int)len - WIFI_MGMT_HDR_LEN,
                       ssid, fixed_len))
    return;
  if (ssid[0] == '\0') return;      // wildcard/broadcast probe
  if (surv_ignore_ssid(ssid)) return;
  char m2[18];
  wifi_mac_to_str(a2, m2);
  if (surv_ignore_mac(m2)) return;

  // Surveillance camera / recording keyword.
  const SsidKeyword* k = ssid_keyword_match(ssid);
  if (k) {
    WifiSeen* s = wifi_seen_get(a2);
    if (s && !(s->flags & SEEN_SSID)) {
      s->flags |= SEEN_SSID;
      emit_wifi_ssid(a2, ssid, k, channel, rssi);
    }
  }

  // Hacking / pentest device keyword (independent of the above).
#if ENABLE_HACKING_DETECTION
  const HackSsid* h = hacking_ssid_match(ssid);
  if (h) {
    WifiSeen* s = wifi_seen_get(a2);
    if (s && !(s->flags & SEEN_HACK)) {
      s->flags |= SEEN_HACK;
      s_hacking_hits++;
      emit_hacking_wifi(a2, ssid, h, channel, rssi);
    }
  }
#endif
}

// ---------------------------------------------------------------------------
// BLE — parse advertisement AD structures and match tracker signatures.
// AD structure: [length][type][data...]; length covers type+data.
// ---------------------------------------------------------------------------
void surveillance_ble_adv(const char* mac, int8_t rssi,
                          const uint8_t* payload, uint8_t len) {
  const char* vendor = nullptr;
  const char* category = nullptr;
  const char* sig = nullptr;
  char name[32] = {0};  // advertised local name, if any

  int i = 0;
  while (i + 1 < len) {
    uint8_t ad_len = payload[i];
    if (ad_len == 0 || i + 1 + ad_len > len) break;
    uint8_t ad_type = payload[i + 1];
    const uint8_t* d = &payload[i + 2];
    int dlen = ad_len - 1;

    if (ad_type == 0xFF && dlen >= 2) {                 // manufacturer specific
      uint16_t cid = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
      if (cid == 0x004C && dlen >= 3 && d[2] == 0x12) { // Apple Find My offline
        vendor = "Apple"; category = "tracker"; sig = "find-my (airtag/offline)";
      }
    } else if ((ad_type == 0x02 || ad_type == 0x03) && dlen >= 2) {  // 16-bit UUIDs
      for (int k = 0; k + 1 < dlen; k += 2) {
        uint16_t u = (uint16_t)d[k] | ((uint16_t)d[k + 1] << 8);
        if (u == 0xFEED || u == 0xFEEC) { vendor = "Tile"; category = "tracker"; sig = "tile"; }
      }
    } else if (ad_type == 0x16 && dlen >= 2) {          // service data (16-bit)
      uint16_t u = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
      if (u == 0xFD5A)                      { vendor = "Samsung"; category = "tracker"; sig = "smarttag"; }
      else if (u == 0xFEED || u == 0xFEEC)  { vendor = "Tile";    category = "tracker"; sig = "tile"; }
    } else if (ad_type == 0x08 || ad_type == 0x09) {    // shortened/complete local name
      int n = dlen; if (n > 31) n = 31;
      for (int j = 0; j < n; j++) {
        uint8_t c = d[j];  // keep printable so it can't corrupt the JSON
        name[j] = (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') ? c : '?';
      }
      name[n] = '\0';
    }
    i += 1 + ad_len;
  }

  // Hacking device by BLE name (e.g. Flipper Zero) takes priority over tracker.
#if ENABLE_HACKING_DETECTION
  if (name[0]) {
    const HackName* h = hacking_ble_name_match(name);
    if (h) {
      if (surv_ignore_mac(mac)) return;
      if (ble_already_alerted(mac)) return;
      s_hacking_hits++;
      char hb[288];
      snprintf(hb, sizeof(hb),
        "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"hacking_device\",\"radio\":\"ble\","
        "\"tool\":\"%s\",\"name\":\"%s\",\"mac\":\"%s\",\"rssi\":%d}",
        SENSOR_ID, (unsigned long)millis(), h->tool, name, mac, rssi);
      alert_event(hb);
      return;
    }
  }
#endif

  if (!sig) return;
  if (surv_ignore_mac(mac)) return;
  if (ble_already_alerted(mac)) return;
  s_ble_hits++;

  char buf[288];
  snprintf(buf, sizeof(buf),
    "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"surveillance_device\",\"radio\":\"ble\","
    "\"category\":\"%s\",\"vendor\":\"%s\",\"signature\":\"%s\",\"mac\":\"%s\",\"rssi\":%d}",
    SENSOR_ID, (unsigned long)millis(), category, vendor, sig, mac, rssi);
  alert_event(buf);
}

uint32_t surveillance_hacking_hits() { return s_hacking_hits; }

uint32_t surveillance_ble_hits() { return s_ble_hits; }
