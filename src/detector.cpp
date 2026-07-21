#include "detector.h"
#include "alert.h"
#include "config.h"
#include "ieee80211.h"
#include "surveillance.h"

#include <Arduino.h>
#include <string.h>
#include <strings.h>  // strcasecmp

// ---------------------------------------------------------------------------
// Counters (for heartbeats / at-a-glance health)
// ---------------------------------------------------------------------------
static volatile uint32_t s_frames  = 0;  // all management frames seen
static volatile uint32_t s_beacons = 0;
static volatile uint32_t s_deauths = 0;  // deauth + disassoc
static volatile uint32_t s_alerts  = 0;

// ---------------------------------------------------------------------------
// Deauth/disassoc flood detection (sliding window, global)
// ---------------------------------------------------------------------------
static uint32_t s_win_start   = 0;
static uint32_t s_deauth_count = 0;
static bool     s_flood_alerted = false;

// ---------------------------------------------------------------------------
// AP registry — remembers BSSIDs so evil-twin/unknown-SSID alerts fire once
// per offender instead of once per beacon (beacons arrive ~10x/second).
// ---------------------------------------------------------------------------
#define MAX_APS 96
#define ALERTED_EVILTWIN 0x1
#define ALERTED_UNKNOWN  0x2

struct ApRecord {
  uint8_t bssid[6];
  uint8_t alerted;  // bitmask of ALERTED_* already emitted for this BSSID
  bool    used;
};
static ApRecord s_aps[MAX_APS];

static ApRecord* ap_lookup_or_insert(const uint8_t* bssid) {
  int free_slot = -1;
  for (int i = 0; i < MAX_APS; i++) {
    if (s_aps[i].used) {
      if (memcmp(s_aps[i].bssid, bssid, 6) == 0) return &s_aps[i];
    } else if (free_slot < 0) {
      free_slot = i;
    }
  }
  if (free_slot < 0) return nullptr;  // table full — silently drop (rare)
  ApRecord* r = &s_aps[free_slot];
  memcpy(r->bssid, bssid, 6);
  r->alerted = 0;
  r->used = true;
  return r;
}

// ---------------------------------------------------------------------------
static void handle_deauth(uint8_t subtype, const uint8_t* a1,
                          const uint8_t* a2, const uint8_t* a3,
                          int8_t rssi, uint8_t channel) {
  s_deauths++;
  uint32_t now = millis();
  if ((uint32_t)(now - s_win_start) > DEAUTH_WINDOW_MS) {
    s_win_start = now;
    s_deauth_count = 0;
    s_flood_alerted = false;
  }
  s_deauth_count++;

  if (s_deauth_count >= DEAUTH_FLOOD_THRESHOLD && !s_flood_alerted) {
    s_flood_alerted = true;
    s_alerts++;
    char src[18], dst[18], bss[18];
    wifi_mac_to_str(a2, src);
    wifi_mac_to_str(a1, dst);
    wifi_mac_to_str(a3, bss);
    char buf[288];
    snprintf(buf, sizeof(buf),
      "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"deauth_flood\",\"frame\":\"%s\","
      "\"count\":%lu,\"window_ms\":%d,\"channel\":%u,"
      "\"src\":\"%s\",\"dst\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d}",
      SENSOR_ID, (unsigned long)now,
      subtype == WIFI_SUBTYPE_DEAUTH ? "deauth" : "disassoc",
      (unsigned long)s_deauth_count, DEAUTH_WINDOW_MS, channel,
      src, dst, bss, rssi);
    alert_event(buf);
  }
}

static void handle_beacon(const uint8_t* frame, uint16_t len,
                          const uint8_t* bssid, int8_t rssi, uint8_t channel) {
  s_beacons++;
  char ssid[33];
  if (!wifi_parse_ssid(frame + WIFI_MGMT_HDR_LEN, (int)len - WIFI_MGMT_HDR_LEN, ssid))
    return;

  char bss[18];
  wifi_mac_to_str(bssid, bss);

  // Is this SSID one we trust, and does this BSSID match an allowed one?
  bool ssid_is_trusted = false;
  bool bssid_matches   = false;
  const char* expected_bssid = "";
  for (size_t i = 0; i < sizeof(kTrustedAps) / sizeof(kTrustedAps[0]); i++) {
    if (strcmp(ssid, kTrustedAps[i].ssid) == 0) {
      ssid_is_trusted = true;
      expected_bssid = kTrustedAps[i].bssid;
      if (strcasecmp(bss, kTrustedAps[i].bssid) == 0) { bssid_matches = true; break; }
    }
  }

  if (ssid_is_trusted && !bssid_matches) {
    // Our SSID, broadcast by a MAC we don't recognise -> possible evil twin.
    ApRecord* r = ap_lookup_or_insert(bssid);
    if (r && !(r->alerted & ALERTED_EVILTWIN)) {
      r->alerted |= ALERTED_EVILTWIN;
      s_alerts++;
      char buf[320];
      snprintf(buf, sizeof(buf),
        "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"evil_twin\",\"ssid\":\"%s\","
        "\"bssid\":\"%s\",\"expected_bssid\":\"%s\",\"channel\":%u,\"rssi\":%d}",
        SENSOR_ID, (unsigned long)millis(), ssid, bss, expected_bssid, channel, rssi);
      alert_event(buf);
    }
    return;
  }

#if ALERT_UNKNOWN_SSID
  if (!ssid_is_trusted) {
    ApRecord* r = ap_lookup_or_insert(bssid);
    if (r && !(r->alerted & ALERTED_UNKNOWN)) {
      r->alerted |= ALERTED_UNKNOWN;
      s_alerts++;
      char buf[288];
      snprintf(buf, sizeof(buf),
        "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"unknown_ssid\",\"ssid\":\"%s\","
        "\"bssid\":\"%s\",\"channel\":%u,\"rssi\":%d}",
        SENSOR_ID, (unsigned long)millis(), ssid, bss, channel, rssi);
      alert_event(buf);
    }
  }
#endif
}

// ---------------------------------------------------------------------------
void detector_init() {
  memset(s_aps, 0, sizeof(s_aps));
  s_win_start = millis();
}

void detector_handle(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel) {
  if (len < WIFI_MGMT_HDR_LEN) return;
  if (wifi_frame_type(frame) != WIFI_TYPE_MGMT) return;  // filter should ensure this
  s_frames++;

  uint8_t subtype = wifi_frame_subtype(frame);

#if ENABLE_SURVEILLANCE_WIFI
  surveillance_wifi_frame(frame, len, subtype, rssi, channel);
#endif

  switch (subtype) {
    case WIFI_SUBTYPE_DEAUTH:
    case WIFI_SUBTYPE_DISASSOC:
      handle_deauth(subtype, wifi_addr1(frame), wifi_addr2(frame),
                    wifi_addr3(frame), rssi, channel);
      break;
    case WIFI_SUBTYPE_BEACON:
    case WIFI_SUBTYPE_PROBE_RESP:
      handle_beacon(frame, len, wifi_addr3(frame), rssi, channel);
      break;
    default:
      break;
  }
}

void detector_heartbeat_json(char* buf, size_t buf_len, uint8_t channel) {
  int ap_count = 0;
  for (int i = 0; i < MAX_APS; i++) if (s_aps[i].used) ap_count++;
  snprintf(buf, buf_len,
    "{\"sensor\":\"%s\",\"ts\":%lu,\"type\":\"heartbeat\",\"channel\":%u,"
    "\"mgmt_frames\":%lu,\"beacons\":%lu,\"deauths\":%lu,\"aps_seen\":%d,"
    "\"ble_trackers\":%lu,\"alerts\":%lu}",
    SENSOR_ID, (unsigned long)millis(), channel,
    (unsigned long)s_frames, (unsigned long)s_beacons,
    (unsigned long)s_deauths, ap_count,
    (unsigned long)surveillance_ble_hits(), (unsigned long)s_alerts);
}
