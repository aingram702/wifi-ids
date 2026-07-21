// sniffer.h — Puts the radio in promiscuous mode and hops channels.
#pragma once

#include <stdint.h>

// Bring up Wi-Fi in promiscuous mode filtered to management frames, register
// the RX callback (which feeds the detector), and park on the first channel.
void sniffer_start();

// Advance channel hopping when the dwell time has elapsed. Call from loop().
void sniffer_service();

// The channel the radio is currently parked on.
uint8_t sniffer_current_channel();
