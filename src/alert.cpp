#include "alert.h"
#include "config.h"
#include <Arduino.h>

// The XIAO ESP32-S3's user LED is on GPIO21 and is active-LOW.
#ifndef LED_BUILTIN
#define LED_BUILTIN 21
#endif
#define LED_ON  LOW
#define LED_OFF HIGH

static uint32_t s_led_off_at = 0;  // millis() deadline to switch the LED back off

void alert_init() {
#if ALERT_LED_ENABLED
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LED_OFF);
#endif
}

void alert_event(const char* json_line) {
  // One alert per line — trivially greppable and parseable downstream.
  Serial.println(json_line);
#if ALERT_LED_ENABLED
  digitalWrite(LED_BUILTIN, LED_ON);
  s_led_off_at = millis() + 120;  // 120 ms blink, extended if alerts keep coming
#endif
}

void alert_service() {
#if ALERT_LED_ENABLED
  if (s_led_off_at != 0 && (int32_t)(millis() - s_led_off_at) >= 0) {
    digitalWrite(LED_BUILTIN, LED_OFF);
    s_led_off_at = 0;
  }
#endif
}
