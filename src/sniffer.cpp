#include "sniffer.h"
#include "detector.h"
#include "config.h"

#include <Arduino.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"

static const size_t kNumChannels = sizeof(kChannels) / sizeof(kChannels[0]);
static size_t   s_chan_idx  = 0;
static uint32_t s_last_hop  = 0;

// Called by the Wi-Fi driver for every frame that passes the promiscuous
// filter. Runs in the Wi-Fi task context — keep it lean.
static void promisc_rx(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;  // filter is set to MGMT, but be safe
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  detector_handle(pkt->payload, pkt->rx_ctrl.sig_len,
                  pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
}

void sniffer_start() {
  // Bring up just enough of the Wi-Fi stack for a passive listener: NVS for
  // calibration data, the default event loop, and the driver in NULL mode
  // (no STA/AP association — we only sniff).
  esp_err_t nvs = nvs_flash_init();
  if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  esp_event_loop_create_default();  // harmless if already created by the core

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  // Only care about management frames (beacons, probe resp, deauth, disassoc).
  // Filtering here keeps the RX callback off the data-frame firehose.
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promisc_rx);
  esp_wifi_set_promiscuous(true);

  esp_wifi_set_channel(kChannels[0], WIFI_SECOND_CHAN_NONE);
  s_chan_idx = 0;
  s_last_hop = millis();
}

void sniffer_service() {
  if (kNumChannels <= 1) return;
  uint32_t now = millis();
  if ((uint32_t)(now - s_last_hop) >= CHANNEL_DWELL_MS) {
    s_last_hop = now;
    s_chan_idx = (s_chan_idx + 1) % kNumChannels;
    esp_wifi_set_channel(kChannels[s_chan_idx], WIFI_SECOND_CHAN_NONE);
  }
}

uint8_t sniffer_current_channel() {
  return kChannels[s_chan_idx];
}
