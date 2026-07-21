# Wi-Fi IDS Sensor (XIAO ESP32-S3)

A cheap, passive Wi-Fi intrusion-detection sensor built on the
[Seeed Studio XIAO ESP32-S3](https://wiki.seeedstudio.com/xiao_esp32s3_getting_started/).
It puts the radio in **promiscuous (monitor) mode**, hops across 2.4 GHz
channels, and raises alerts for:

- **Deauth / disassoc floods** — the classic Wi-Fi denial-of-service, and the
  first move in most evil-twin attacks.
- **Evil twins** — a network you trust (SSID) being broadcast from a MAC
  address (BSSID) you *don't* trust.
- **Unexpected SSIDs** (optional) — any access point that isn't on your
  allow-list.

Alerts come out as one-line JSON over USB serial and blink the onboard LED.
Because the whole thing is a ~$7 board, you can flash several and scatter them
around a building as a **sensor grid**, all feeding one collector.

> ⚠️ **Use responsibly.** This is a passive listener — it never transmits,
> deauths, or injects. Even so, monitoring Wi-Fi management frames may be
> regulated where you live. Only run it on networks and premises you own or are
> authorised to monitor.

---

## How it works

The ESP32-S3 radio can only listen to one channel at a time, so the firmware
dwells on each channel (`CHANNEL_DWELL_MS`, default 300 ms) before hopping to
the next. A promiscuous-mode filter set to **management frames only** keeps the
CPU off the data-frame firehose, so the sensor spends its cycles on the frames
that actually matter for detection.

```
     802.11 mgmt frames
   ┌──────────────────────┐
   │  sniffer.cpp          │  promiscuous RX + channel hopping
   └──────────┬───────────┘
              │ frame, rssi, channel
   ┌──────────▼───────────┐
   │  detector.cpp         │  deauth-flood window · evil-twin / rogue-AP checks
   └──────────┬───────────┘
              │ JSON alert
   ┌──────────▼───────────┐
   │  alert.cpp            │  Serial (USB) + onboard LED
   └──────────────────────┘
```

**Detections in detail**

| Alert | Trigger |
|-------|---------|
| `deauth_flood` | ≥ `DEAUTH_FLOOD_THRESHOLD` deauth/disassoc frames within `DEAUTH_WINDOW_MS` (sliding window). |
| `evil_twin` | A beacon/probe-response advertises a trusted SSID from a BSSID that isn't in that SSID's allow-list. Fires once per offending BSSID. |
| `unknown_ssid` | (Opt-in) Any SSID not in `kTrustedAps`. Off by default — noisy near neighbours. |
| `heartbeat` | Emitted every `HEARTBEAT_MS`; counters for liveness / tuning. |

---

## Hardware

- **Seeed Studio XIAO ESP32-S3** (the plain one is fine; the "Sense" variant
  works too).
- A USB-C cable. That's it — the onboard PCB antenna and user LED are all you
  need. Power it from a USB charger, a battery pack, or a host PC.

For a grid, one board per coverage area. They don't need to talk to each
other; each streams JSON to whatever it's plugged into.

---

## Build & flash

### PlatformIO (recommended)

```bash
pip install platformio          # once
git clone <this repo> && cd wifi-ids
pio run -t upload -t monitor     # build, flash, open the serial monitor
```

### Arduino IDE

1. Install the **esp32** board package (Boards Manager → "esp32" by Espressif).
2. Select **XIAO_ESP32S3** as the board.
3. Under *Tools*, set **USB CDC On Boot: Enabled** (so the serial monitor works
   over the single USB-C port).
4. Copy the contents of `src/` into a sketch folder named `wifi-ids`
   (rename `main.cpp` → `wifi-ids.ino`), then Upload.

You should immediately see a `boot` line, then `heartbeat` lines every 10 s:

```json
{"sensor":"xiao-sensor-01","type":"boot","msg":"wifi-ids sensor online"}
{"sensor":"xiao-sensor-01","ts":10021,"type":"heartbeat","channel":6,"mgmt_frames":842,"beacons":790,"deauths":0,"aps_seen":14,"alerts":0}
```

---

## Configure

Everything lives in [`src/config.h`](src/config.h):

```c
#define SENSOR_ID "xiao-sensor-01"   // unique per board in a grid

// APs you trust: SSID -> allowed BSSID. Anything else claiming these SSIDs
// is flagged as an evil twin. One row per AP (mesh = several rows).
static const TrustedAp kTrustedAps[] = {
  {"MyHomeWiFi", "aa:bb:cc:dd:ee:ff"},
};

#define DEAUTH_FLOOD_THRESHOLD 20    // deauth frames per second before alerting
```

**Finding your AP's BSSID:** run the sensor with `ALERT_UNKNOWN_SSID 1`
temporarily, or check your router's admin page / `iw dev` / a phone Wi-Fi
analyzer app. The BSSID is the AP's MAC address, lower-case with colons.

Tuning tips:
- **Fewer channels, longer dwell** (`{1, 6, 11}`) catches fast floods more
  reliably at the cost of coverage.
- Lower `DEAUTH_FLOOD_THRESHOLD` for a quieter RF environment; raise it if you
  get false positives from a busy network.
- Regions outside the EU: drop channels 12–13 from `kChannels`.

---

## The sensor grid: collecting alerts

Each sensor just needs power and something reading its serial port. The
included collector tails one or many ports, colorises alerts, keeps a per-sensor
tally, and can log everything to newline-delimited JSON.

```bash
pip install pyserial

# one sensor
python3 tools/collector.py /dev/ttyACM0

# several, logging to a file you can grep/replay later
python3 tools/collector.py /dev/ttyACM0 /dev/ttyACM1 --log grid.ndjson

# let it find likely ESP32-S3 ports itself
python3 tools/collector.py --auto
```

Example output:

```
[13:37:04] xiao-sensor-01   DEAUTH FLOOD  63 deauth frames/1000ms  ch6  src=de:ad:be:ef:00:01 bssid=aa:bb:cc:dd:ee:ff rssi=-41
[13:37:09] xiao-sensor-02   EVIL TWIN     ssid='MyHomeWiFi'  rogue=12:34:56:78:9a:bc expected=aa:bb:cc:dd:ee:ff  ch11 rssi=-58
```

Because the wire format is just JSON lines, you can skip the collector entirely
and pipe a port into anything — a log shipper, an MQTT bridge, `jq`, a SIEM.
Each Raspberry Pi / mini-PC / spare laptop can host a handful of sensors over a
USB hub, and the `sensor` field keeps every alert attributable.

---

## Repo layout

```
platformio.ini      Board + build configuration
src/
  main.cpp          setup()/loop(): wiring, heartbeat
  config.h          ← the file you edit: identity, thresholds, trusted APs
  sniffer.{h,cpp}   Promiscuous mode + channel hopping
  detector.{h,cpp}  Deauth-flood + evil-twin/rogue-AP detection
  ieee80211.h       802.11 management-frame parsing helpers
  alert.{h,cpp}     JSON-over-serial + LED alert sink
tools/
  collector.py      Host-side grid collector
```

---

## Limitations & notes

- **One channel at a time.** While hopping, a flood on another channel can be
  partly missed. For a critical channel, pin `kChannels` to just that one.
- **2.4 GHz only** in the default config — that's where deauth/evil-twin
  attacks against legacy clients live. The ESP32-S3 has no 5 GHz radio.
- Detection is **heuristic**. Deauth thresholds and the trusted-AP list are
  yours to tune; treat alerts as leads, not verdicts.
- The sensor never associates, transmits, or interferes with any network.

## License

MIT — see [LICENSE](LICENSE).
