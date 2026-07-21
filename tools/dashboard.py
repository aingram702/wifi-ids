#!/usr/bin/env python3
"""dashboard.py — Live web GUI for the Wi-Fi IDS sensor grid.

Reads the same one-line JSON that sensors emit over USB serial, keeps grid
state (sensors, detected devices, alert counts, recent events), and serves a
browser dashboard that updates in real time over Server-Sent Events.

Uses only the Python standard library plus pyserial (already needed by the
collector). No web framework, no build step, works offline.

Examples:
    # Live, from sensors on these ports
    ./dashboard.py /dev/ttyACM0 /dev/ttyACM1

    # Auto-detect sensor ports
    ./dashboard.py --auto

    # No hardware handy? Watch synthetic traffic to see the UI:
    ./dashboard.py --demo

    # Replay a captured log (ndjson from collector.py --log)
    ./dashboard.py --replay grid.ndjson

Then open http://localhost:8080  (change with --host / --port).
"""
import argparse
import json
import os
import queue
import random
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(HERE, "dashboard.html")

ALERT_TYPES = ("deauth_flood", "evil_twin", "unknown_ssid", "surveillance_device")
DEVICE_TYPES = ("surveillance_device", "evil_twin", "unknown_ssid")


# --------------------------------------------------------------------------
# Shared state + pub/sub hub
# --------------------------------------------------------------------------
class Hub:
    """Fan-out of events to all connected browsers, plus authoritative state."""

    def __init__(self, recent_max=800):
        self.lock = threading.Lock()
        self.subs = set()                 # set[queue.Queue]
        self.seq = 0
        self.recent = []                  # list[dict], oldest-first, capped
        self.recent_max = recent_max
        self.sensors = {}                 # id -> latest heartbeat-ish fields
        self.devices = {}                 # mac/bssid -> device record
        self.counts = {t: 0 for t in ALERT_TYPES}

    def publish(self, obj):
        with self.lock:
            self.seq += 1
            obj["_seq"] = self.seq
            obj.setdefault("_rx", int(time.time() * 1000))
            self._ingest(obj)
            self.recent.append(obj)
            if len(self.recent) > self.recent_max:
                self.recent = self.recent[-self.recent_max:]
            data = json.dumps(obj)
            dead = []
            for q in self.subs:
                try:
                    q.put_nowait(data)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subs.discard(q)

    def _ingest(self, ev):
        sensor = ev.get("sensor")
        if sensor:
            s = self.sensors.setdefault(sensor, {"sensor": sensor})
            s["last_seen"] = ev["_rx"]
            if ev.get("type") == "heartbeat":
                for k in ("channel", "mgmt_frames", "beacons", "deauths",
                          "aps_seen", "ble_trackers", "alerts"):
                    if k in ev:
                        s[k] = ev[k]
        t = ev.get("type")
        if t in ALERT_TYPES:
            self.counts[t] = self.counts.get(t, 0) + 1
        if t in DEVICE_TYPES:
            key = ev.get("mac") or ev.get("bssid")
            if key:
                d = self.devices.setdefault(
                    key, {"key": key, "first_seen": ev["_rx"], "count": 0})
                d["count"] += 1
                d["last_seen"] = ev["_rx"]
                d["rssi"] = ev.get("rssi")
                d["sensor"] = sensor
                if t == "surveillance_device":
                    d.update(name=ev.get("vendor"), category=ev.get("category"),
                             radio=ev.get("radio"), ssid=ev.get("ssid"),
                             detail=ev.get("signature"))
                elif t == "evil_twin":
                    d.update(name=ev.get("ssid"), category="rogue",
                             radio="wifi", detail="evil twin")
                else:
                    d.update(name=ev.get("ssid"), category="rogue",
                             radio="wifi", detail="unknown ssid")

    def snapshot(self):
        with self.lock:
            return {
                "sensors": self.sensors,
                "devices": list(self.devices.values()),
                "counts": self.counts,
                "recent": self.recent[-400:],
                "last_seq": self.seq,
            }

    def subscribe(self):
        q = queue.Queue(maxsize=2000)
        with self.lock:
            self.subs.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subs.discard(q)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
def make_handler(hub):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):        # quiet
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index"):
                try:
                    with open(HTML_PATH, "rb") as f:
                        body = f.read()
                except OSError:
                    body = b"<h1>dashboard.html not found next to dashboard.py</h1>"
                self._send(200, body, "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                body = json.dumps(hub.snapshot()).encode()
                self._send(200, body, "application/json")
            elif self.path.startswith("/events"):
                self._stream_events()
            else:
                self._send(404, b"not found", "text/plain")

        def _stream_events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            q = hub.subscribe()
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    try:
                        data = q.get(timeout=15)
                        self.wfile.write(b"data: " + data.encode() + b"\n\n")
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")   # keep-alive
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

    return Handler


# --------------------------------------------------------------------------
# Event sources
# --------------------------------------------------------------------------
def serial_reader(port, baud, hub, logfp):
    import serial  # type: ignore
    while True:
        try:
            with serial.Serial(port, baud, timeout=1) as ser:
                print(f"[*] connected to {port} @ {baud}")
                for raw in ser:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    if logfp:
                        logfp.write(line + "\n"); logfp.flush()
                    try:
                        hub.publish(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except Exception as e:  # noqa: BLE001 (serial.SerialException et al.)
            print(f"[!] {port}: {e} — retrying in 3s")
            time.sleep(3)


def replay_reader(path, hub, speed):
    with open(path) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    print(f"[*] replaying {len(lines)} events from {path} (speed x{speed})")
    for ln in lines:
        try:
            hub.publish(json.loads(ln))
        except json.JSONDecodeError:
            continue
        time.sleep(0.15 / max(speed, 0.01))


def demo_reader(hub):
    """Generate plausible synthetic traffic so the UI can be seen without HW."""
    print("[*] demo mode — generating synthetic sensor traffic")
    sensors = ["xiao-sensor-01", "xiao-sensor-02", "xiao-sensor-03"]
    for s in sensors:
        hub.publish({"sensor": s, "type": "boot", "msg": "wifi-ids sensor online"})
    cams = [("Hikvision", "camera", "44:19:b6"), ("Amazon", "camera", "fc:65:de"),
            ("Ubiquiti", "networking", "78:8a:20"), ("Nest", "camera", "18:b4:30")]
    trackers = [("Apple", "find-my (airtag/offline)"), ("Tile", "tile"),
                ("Samsung", "smarttag")]
    counters = {s: {"mgmt": 0, "beacons": 0, "deauths": 0, "aps": 0,
                    "trk": 0, "alerts": 0} for s in sensors}
    rnd = random.Random(1)

    def rmac(prefix=None):
        p = prefix or "%02x:%02x:%02x" % tuple(rnd.randint(0, 255) for _ in range(3))
        return p + ":%02x:%02x:%02x" % tuple(rnd.randint(0, 255) for _ in range(3))

    tick = 0
    while True:
        s = rnd.choice(sensors)
        c = counters[s]
        c["mgmt"] += rnd.randint(20, 120)
        c["beacons"] += rnd.randint(15, 90)
        c["aps"] = min(60, c["aps"] + rnd.randint(0, 1))
        roll = rnd.random()
        if roll < 0.12:                                   # surveillance: camera
            v, cat, pfx = rnd.choice(cams); c["alerts"] += 1
            hub.publish({"sensor": s, "type": "surveillance_device", "radio": "wifi",
                         "match": "oui", "category": cat, "vendor": v,
                         "mac": rmac(pfx), "channel": rnd.choice([1, 6, 11]),
                         "rssi": -rnd.randint(40, 80)})
        elif roll < 0.20:                                 # surveillance: BLE tracker
            v, sig = rnd.choice(trackers); c["trk"] += 1; c["alerts"] += 1
            hub.publish({"sensor": s, "type": "surveillance_device", "radio": "ble",
                         "category": "tracker", "vendor": v, "signature": sig,
                         "mac": rmac(), "rssi": -rnd.randint(45, 85)})
        elif roll < 0.24:                                 # deauth flood
            c["deauths"] += 40; c["alerts"] += 1
            hub.publish({"sensor": s, "type": "deauth_flood", "frame": "deauth",
                         "count": rnd.randint(25, 90), "window_ms": 1000,
                         "channel": rnd.choice([1, 6, 11]), "src": rmac(),
                         "dst": "ff:ff:ff:ff:ff:ff", "bssid": rmac("aa:bb:cc"),
                         "rssi": -rnd.randint(35, 70)})
        elif roll < 0.28:                                 # evil twin
            c["alerts"] += 1
            hub.publish({"sensor": s, "type": "evil_twin", "ssid": "CoffeeShopWiFi",
                         "bssid": rmac("de:ad:be"), "expected_bssid": "aa:bb:cc:dd:ee:ff",
                         "channel": rnd.choice([1, 6, 11]), "rssi": -rnd.randint(40, 75)})
        elif roll < 0.32:                                 # unknown ssid
            c["alerts"] += 1
            hub.publish({"sensor": s, "type": "unknown_ssid",
                         "ssid": "NETGEAR-" + str(rnd.randint(10, 99)),
                         "bssid": rmac(), "channel": rnd.choice([1, 6, 11]),
                         "rssi": -rnd.randint(50, 85)})
        tick += 1
        if tick % 4 == 0:                                 # heartbeats
            for sid in sensors:
                cc = counters[sid]
                hub.publish({"sensor": sid, "type": "heartbeat",
                             "channel": rnd.choice(list(range(1, 12))),
                             "mgmt_frames": cc["mgmt"], "beacons": cc["beacons"],
                             "deauths": cc["deauths"], "aps_seen": cc["aps"],
                             "ble_trackers": cc["trk"], "alerts": cc["alerts"]})
        time.sleep(rnd.uniform(0.4, 1.3))


def auto_ports():
    try:
        from serial.tools import list_ports  # type: ignore
    except ImportError:
        return []
    found = []
    for p in list_ports.comports():
        blob = f"{p.description} {p.hwid}".lower()
        if any(t in blob for t in ("esp32", "usb jtag", "cp210", "ch340", "acm")):
            found.append(p.device)
    return found


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Wi-Fi IDS grid web dashboard")
    ap.add_argument("ports", nargs="*", help="serial ports (e.g. /dev/ttyACM0)")
    ap.add_argument("--auto", action="store_true", help="auto-detect sensor ports")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log", help="append every JSON line to this file (ndjson)")
    ap.add_argument("--replay", help="replay an ndjson log instead of reading serial")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    ap.add_argument("--demo", action="store_true", help="generate synthetic traffic")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default localhost-only; use 0.0.0.0 to "
                         "expose to the LAN — the dashboard has no auth, so only "
                         "do that on a trusted network)")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    hub = Hub()
    logfp = open(args.log, "a") if args.log else None

    if args.demo:
        threading.Thread(target=demo_reader, args=(hub,), daemon=True).start()
    elif args.replay:
        threading.Thread(target=replay_reader, args=(args.replay, hub, args.speed),
                         daemon=True).start()
    else:
        ports = list(args.ports)
        if args.auto:
            ports += [p for p in auto_ports() if p not in ports]
        if not ports:
            ap.error("no source: give ports, or use --auto / --demo / --replay")
        try:
            import serial  # noqa: F401
        except ImportError:
            ap.error("pyserial is required for live capture:  pip install pyserial")
        for port in ports:
            threading.Thread(target=serial_reader,
                             args=(port, args.baud, hub, logfp), daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(hub))
    shown = "localhost" if args.host in ("0.0.0.0", "", "127.0.0.1") else args.host
    print(f"[*] dashboard: http://{shown}:{args.port}   (Ctrl-C to quit)")
    if args.host in ("0.0.0.0", ""):
        print("[!] bound to all interfaces — dashboard has no auth; "
              "make sure you trust this network")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] shutting down")
        if logfp:
            logfp.close()


if __name__ == "__main__":
    main()
