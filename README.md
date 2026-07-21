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
- **Surveillance devices** — Wi-Fi cameras and gear (Flock, Ring, Nest,
  Hikvision, Dahua, Axis, Ubiquiti…) matched by vendor OUI and SSID keywords,
  **plus Bluetooth trackers** (Apple Find My / AirTag, Tile, Samsung SmartTag)
  via a built-in BLE scanner.

Alerts come out as one-line JSON over USB serial and blink the onboard LED.
Because the whole thing is a ~$7 board, you can flash several and scatter them
around a building as a **sensor grid**, all feeding one collector — with a
[live web dashboard](#web-dashboard) for viewing it.

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
| `surveillance_device` | A management-frame MAC matches a surveillance-vendor OUI, an SSID matches a device keyword, or a BLE advertisement matches a known tracker. Fires once per device. |
| `heartbeat` | Emitted every `HEARTBEAT_MS`; counters for liveness / tuning. |

### Surveillance & tracker detection

The sensor also flags physical-surveillance and tracking gear — the stuff that
watches *you* rather than attacks your network:

Scope is deliberately limited to **surveillance and recording gear** — cameras,
video doorbells, NVR/DVR ecosystems, body/fleet/ALPR cameras, action cams,
camera drones, and Bluetooth item trackers. General networking, phones, and PCs
are excluded to keep false alarms down.

**Wi-Fi cameras & gear** are matched two ways, from the management frames the
sensor already sees:
- **Vendor OUI** — the first 3 bytes of a device's MAC identify its maker. The
  seed table in [`src/signatures.h`](src/signatures.h) covers Hikvision, Dahua,
  Axis, Vivotek, Mobotix, GeoVision, ACTi, Wyze, Ubiquiti/UniFi, Amazon
  (Ring/Blink), Google/Nest, plus GoPro (recording) and DJI (drone).
- **SSID keywords** — an AP broadcasting (or a client probing for) a telltale
  SSID (`flock`, `axon`, `verkada`, `reolink`, `ezviz`, `tapo`, `eufy`, `wyze`,
  `arlo`, `gopro`, `dji-`, `cctv`, `doorbell`, …) is flagged. Each hit carries a
  category: `camera`, `recording`, `drone`, or `surveillance`.

**Bluetooth trackers** are caught by a BLE scanner running alongside the Wi-Fi
sniffer on the ESP32-S3's second radio: **Apple Find My / AirTag** (offline-
finding advertisement), **Tile** (service UUID 0xFEED/0xFEEC), and **Samsung
SmartTag** (service data 0xFD5A). Useful for spotting an unexpected tracker
that's travelling with you.

**Ignore your own devices.** So the sensor doesn't keep alerting on your own
Ring/Nest/AirTag, list their MACs or SSIDs in `kSurveillanceIgnoreMacs` /
`kSurveillanceIgnoreSsids` in [`src/config.h`](src/config.h) — matches there are
suppressed on both radios.

> **On accuracy:** OUIs are assigned per *vendor*, not per model, and vendors
> own many blocks — so the OUI/keyword lists are a **curated seed, not gospel**.
> A hit means "a device from this vendor is nearby," which is a lead, not a
> verdict. A wrong OUI simply never matches (it can't false-positive on someone
> else's device); the shared Amazon/Google blocks are the exception and can flag
> an Echo/Home speaker as a "camera," so prune those if it bothers you. The lists
> live in one file (`signatures.h`) and are meant to be extended. **Flock
> Safety** cameras are LTE-first and don't reliably beacon on Wi-Fi; the SSID
> keyword catches their provisioning/probe traffic when present, and you can add
> a confirmed OUI to the table as the community documents them.

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
2. Install **NimBLE-Arduino** (Library Manager → "NimBLE-Arduino" by h2zero,
   1.4.x) — needed for BLE tracker detection. Skip this and set
   `ENABLE_BLE_SCAN 0` in `config.h` for a Wi-Fi-only build.
3. Select **XIAO_ESP32S3** as the board, and set **Partition Scheme: Huge App**
   (Wi-Fi + BLE together is a large binary).
4. Under *Tools*, set **USB CDC On Boot: Enabled** (so the serial monitor works
   over the single USB-C port).
5. Copy the contents of `src/` into a sketch folder named `wifi-ids`
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

To extend surveillance detection, edit [`src/signatures.h`](src/signatures.h) —
add rows to `kOuiTable` (vendor MAC prefixes) or `kSsidKeywords`. Toggle the
whole feature with `ENABLE_SURVEILLANCE_WIFI` / `ENABLE_BLE_SCAN` in `config.h`.

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
[13:37:12] xiao-sensor-01   SURVEILLANCE  [wifi] Hikvision (camera) 'oui' mac=44:19:b6:12:34:56 rssi=-63 ch1
[13:37:18] xiao-sensor-02   SURVEILLANCE  [ble] Apple (tracker) 'find-my (airtag/offline)' mac=4d:2a:... rssi=-55
```

Because the wire format is just JSON lines, you can skip the collector entirely
and pipe a port into anything — a log shipper, an MQTT bridge, `jq`, a SIEM.
Each Raspberry Pi / mini-PC / spare laptop can host a handful of sensors over a
USB hub, and the `sensor` field keeps every alert attributable.

### Web dashboard

For a live GUI, `tools/dashboard.py` ingests the same sensor JSON and serves a
browser dashboard that updates in real time (over Server-Sent Events): a live
alert feed, per-sensor status cards, alert counters, and a searchable table of
every detected surveillance device / rogue AP — with **Export CSV** for logging
a survey walk. It's **standard library only** (plus pyserial for live capture)
— no web framework, no build step, works offline.

```bash
# live, from sensors
python3 tools/dashboard.py /dev/ttyACM0 /dev/ttyACM1     # or --auto

# no hardware yet? watch synthetic traffic to see the UI
python3 tools/dashboard.py --demo

# replay a captured log (e.g. from collector.py --log)
python3 tools/dashboard.py --replay grid.ndjson
```

Then open **http://localhost:8080** (change with `--host` / `--port`). The
console `collector.py` and the web `dashboard.py` read the same data — run
either, or both, or point them at a shared `--log` file.

> The dashboard binds to **localhost only** by default and has no
> authentication — the alert stream includes device and AP MAC addresses. To
> view it from another machine, pass `--host 0.0.0.0`, and only do so on a
> network you trust.

---

## Repo layout

```
platformio.ini      Board + build configuration
src/
  main.cpp          setup()/loop(): wiring, heartbeat
  config.h          ← the file you edit: identity, thresholds, trusted APs, toggles
  sniffer.{h,cpp}   Promiscuous mode + channel hopping
  detector.{h,cpp}  Deauth-flood + evil-twin/rogue-AP detection
  surveillance.{h,cpp}  Camera (OUI/SSID) + BLE tracker detection
  signatures.h      ← editable OUI table, SSID keywords, tracker signatures
  ble.{h,cpp}       NimBLE scanner (feeds the surveillance detector)
  ieee80211.h       802.11 management-frame parsing helpers
  alert.{h,cpp}     JSON-over-serial + LED alert sink
tools/
  collector.py      Host-side grid collector (console)
  dashboard.py      Host-side web dashboard server (SSE, stdlib only)
  dashboard.html    The dashboard UI (self-contained, no external assets)
```

---

## Limitations & notes

- **One channel at a time.** While hopping, a flood on another channel can be
  partly missed. For a critical channel, pin `kChannels` to just that one.
- **2.4 GHz only** in the default config — that's where deauth/evil-twin
  attacks against legacy clients live. The ESP32-S3 has no 5 GHz radio.
- Detection is **heuristic**. Deauth thresholds, the trusted-AP list, and the
  surveillance OUI/keyword/tracker signatures are yours to tune; treat alerts as
  leads, not verdicts. OUIs identify a *vendor*, not a specific model.
- **Wi-Fi + BLE share one antenna.** With `ENABLE_BLE_SCAN` on, the ESP32-S3
  coexistence framework time-slices the radio, so both Wi-Fi capture and BLE
  scanning run at a slightly reduced duty cycle. Turn BLE off for maximum Wi-Fi
  sensitivity, or run separate boards for each role in a grid.
- MAC randomization means many client probe requests carry a throwaway MAC;
  OUI matching skips those (locally-administered bit set) and leans on SSID
  keywords instead.
- The sensor is passive: it never associates, transmits Wi-Fi, or sends BLE scan
  requests (passive scan). It only listens.

## License

MIT — see [LICENSE](LICENSE).
