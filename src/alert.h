// alert.h — Where output goes: JSON lines over Serial, plus the onboard LED.
//
// All Serial writes funnel through here and are mutex-serialized, because
// output is produced from three different tasks (the Wi-Fi RX callback, the
// BLE scan callback, and the main loop). Without that lock their println()s
// interleave and corrupt the JSON lines the collector parses.
#pragma once

// Initialise the output sink (LED pin + Serial mutex). Call once from setup(),
// after Serial.begin().
void alert_init();

// Print one line to Serial, serialized against other tasks. Use for status
// output (boot banner, heartbeats) that shouldn't blink the alert LED.
void alert_println(const char* line);

// Emit one alert: same as alert_println() plus a brief LED blink. `json_line`
// is a complete single-line JSON object.
void alert_event(const char* json_line);

// Non-blocking LED housekeeping — turns the LED back off after a blink.
// Call every loop() iteration.
void alert_service();
