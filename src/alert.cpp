#include "alert.h"
#include "config.h"
#include <Arduino.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

// The XIAO ESP32-S3's user LED is on GPIO21 and is active-LOW.
#ifndef LED_BUILTIN
#define LED_BUILTIN 21
#endif
#define LED_ON  LOW
#define LED_OFF HIGH

// Serializes Serial access across the Wi-Fi task, the BLE task, and loop().
static SemaphoreHandle_t s_serial_mtx = nullptr;
static volatile uint32_t s_led_off_at = 0;  // millis() deadline to switch LED off

void alert_init() {
  s_serial_mtx = xSemaphoreCreateMutex();
#if ALERT_LED_ENABLED
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LED_OFF);
#endif
}

void alert_println(const char* line) {
  if (s_serial_mtx) xSemaphoreTake(s_serial_mtx, portMAX_DELAY);
  Serial.println(line);
  if (s_serial_mtx) xSemaphoreGive(s_serial_mtx);
}

void alert_event(const char* json_line) {
  alert_println(json_line);  // one alert per line — greppable, parseable
#if ALERT_LED_ENABLED
  digitalWrite(LED_BUILTIN, LED_ON);
  s_led_off_at = millis() + 120;  // 120 ms blink, extended if alerts keep coming
#endif
}

void alert_service() {
#if ALERT_LED_ENABLED
  uint32_t off = s_led_off_at;
  if (off != 0 && (int32_t)(millis() - off) >= 0) {
    digitalWrite(LED_BUILTIN, LED_OFF);
    s_led_off_at = 0;
  }
#endif
}
