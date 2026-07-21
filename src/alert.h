// alert.h — Where alerts go: a JSON line over Serial, plus the onboard LED.
#pragma once

// Initialise the alert sink (LED pin). Call once from setup().
void alert_init();

// Emit one alert. `json_line` is a complete, single-line JSON object; it is
// printed to Serial verbatim and triggers a brief LED blink.
void alert_event(const char* json_line);

// Non-blocking LED housekeeping — turns the LED back off after a blink.
// Call every loop() iteration.
void alert_service();
