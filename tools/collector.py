#!/usr/bin/env python3
"""collector.py — Read JSON alert lines from one or more Wi-Fi IDS sensors.

Each sensor emits one JSON object per line over its USB serial port. This
script tails those ports, pretty-prints alerts (with color), keeps a running
tally per sensor, and optionally logs every line to a file for later analysis.

Examples:
    # One sensor on a known port
    ./collector.py /dev/ttyACM0

    # A small grid, logging everything to a file
    ./collector.py /dev/ttyACM0 /dev/ttyACM1 --log grid.ndjson

    # Auto-detect likely ESP32-S3 ports
    ./collector.py --auto

Requires pyserial:  pip install pyserial
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime

try:
    import serial            # type: ignore
    from serial.tools import list_ports  # type: ignore
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")

# ANSI colors (skipped automatically when not a TTY)
_COLORS = {
    "deauth_flood":        "\033[1;31m",   # bright red
    "evil_twin":           "\033[1;35m",   # bright magenta
    "unknown_ssid":        "\033[1;33m",   # yellow
    "surveillance_device": "\033[1;34m",   # bright blue
    "heartbeat":           "\033[2;37m",   # dim
    "boot":                "\033[1;36m",   # cyan
}
_RESET = "\033[0m"
_USE_COLOR = sys.stdout.isatty()


def _c(kind: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(kind, '')}{text}{_RESET}"


class Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts: dict = {}   # sensor -> {alert_type -> n}

    def bump(self, sensor: str, kind: str) -> None:
        with self.lock:
            self.counts.setdefault(sensor, {}).setdefault(kind, 0)
            self.counts[sensor][kind] += 1

    def summary(self) -> str:
        with self.lock:
            if not self.counts:
                return "(no data yet)"
            lines = []
            for sensor in sorted(self.counts):
                parts = ", ".join(
                    f"{k}={v}" for k, v in sorted(self.counts[sensor].items())
                )
                lines.append(f"  {sensor}: {parts}")
            return "\n".join(lines)


def format_line(obj: dict) -> str:
    kind = obj.get("type", "?")
    sensor = obj.get("sensor", "?")
    ts = datetime.now().strftime("%H:%M:%S")

    if kind == "deauth_flood":
        body = (f"DEAUTH FLOOD  {obj.get('count')} {obj.get('frame')} frames/"
                f"{obj.get('window_ms')}ms  ch{obj.get('channel')}  "
                f"src={obj.get('src')} bssid={obj.get('bssid')} "
                f"rssi={obj.get('rssi')}")
    elif kind == "evil_twin":
        body = (f"EVIL TWIN     ssid={obj.get('ssid')!r}  "
                f"rogue={obj.get('bssid')} expected={obj.get('expected_bssid')}  "
                f"ch{obj.get('channel')} rssi={obj.get('rssi')}")
    elif kind == "unknown_ssid":
        body = (f"UNKNOWN SSID  ssid={obj.get('ssid')!r} bssid={obj.get('bssid')} "
                f"ch{obj.get('channel')} rssi={obj.get('rssi')}")
    elif kind == "surveillance_device":
        radio = obj.get("radio", "?")
        vendor = obj.get("vendor", "?")
        cat = obj.get("category", "?")
        detail = obj.get("signature") or obj.get("ssid") or obj.get("match", "")
        body = (f"SURVEILLANCE  [{radio}] {vendor} ({cat}) "
                f"{detail!r} mac={obj.get('mac')} rssi={obj.get('rssi')}"
                + (f" ch{obj.get('channel')}" if obj.get("channel") else ""))
    elif kind == "heartbeat":
        body = (f"heartbeat     ch{obj.get('channel')}  "
                f"mgmt={obj.get('mgmt_frames')} beacons={obj.get('beacons')} "
                f"deauths={obj.get('deauths')} aps={obj.get('aps_seen')} "
                f"trackers={obj.get('ble_trackers', 0)} "
                f"alerts={obj.get('alerts')}")
    elif kind == "boot":
        body = f"BOOT          {obj.get('msg', '')}"
    else:
        body = json.dumps(obj)

    return _c(kind, f"[{ts}] {sensor:<16} {body}")


def reader(port: str, baud: int, stats: Stats, logfp) -> None:
    while True:
        try:
            with serial.Serial(port, baud, timeout=1) as ser:
                print(_c("boot", f"[*] connected to {port} @ {baud}"))
                for raw in ser:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    if logfp:
                        logfp.write(line + "\n")
                        logfp.flush()
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        print(f"[{port}] {line}")   # non-JSON boot noise, etc.
                        continue
                    stats.bump(obj.get("sensor", port), obj.get("type", "?"))
                    print(format_line(obj))
        except serial.SerialException as e:
            print(_c("deauth_flood", f"[!] {port}: {e} — retrying in 3s"))
            time.sleep(3)


def auto_ports() -> list:
    found = []
    for p in list_ports.comports():
        blob = f"{p.description} {p.hwid}".lower()
        if any(t in blob for t in ("esp32", "usb jtag", "cp210", "ch340", "acm")):
            found.append(p.device)
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description="Wi-Fi IDS grid collector")
    ap.add_argument("ports", nargs="*", help="serial ports (e.g. /dev/ttyACM0)")
    ap.add_argument("--auto", action="store_true", help="auto-detect sensor ports")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log", help="append every JSON line to this file (ndjson)")
    args = ap.parse_args()

    ports = list(args.ports)
    if args.auto:
        ports += [p for p in auto_ports() if p not in ports]
    if not ports:
        ap.error("no ports given; pass ports explicitly or use --auto")

    logfp = open(args.log, "a") if args.log else None
    stats = Stats()

    threads = []
    for port in ports:
        t = threading.Thread(target=reader, args=(port, args.baud, stats, logfp),
                             daemon=True)
        t.start()
        threads.append(t)

    print(f"[*] watching {len(ports)} sensor(s): {', '.join(ports)}")
    print("[*] Ctrl-C to quit\n")
    try:
        while True:
            time.sleep(30)
            print(_c("heartbeat", "\n--- tally ---\n" + stats.summary() + "\n"))
    except KeyboardInterrupt:
        print("\n" + stats.summary())
        if logfp:
            logfp.close()


if __name__ == "__main__":
    main()
