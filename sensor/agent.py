"""
Passive Threat Detector - live capture sensor.

Reads REAL packets off a network interface, summarises them into flow records,
and ships them to the analyser over HTTP. Standard library only.

Why this exists as a separate program
-------------------------------------
This is the piece that makes the project real rather than a simulation. It also
mirrors the architecture it is modelling:

    [ monitored network ] --> sensor --> (one direction only) --> analyser

The sensor reads packets and sends summaries out. It never injects, replies to,
or modifies traffic, and the analyser has no channel back to it. That is exactly
the constraint a hardware data diode imposes.

Three capture modes
-------------------
  live    real packets from a live interface        (needs Administrator/root)
  pcap    real packets from a .pcap file           (no privileges needed)
  --list  show interfaces and exit

Usage
-----
  python agent.py --backend http://127.0.0.1:8000
  python agent.py --pcap capture.pcap --backend http://127.0.0.1:8000
  python agent.py --list

Run the Windows shell as Administrator for live mode. Promiscuous capture is a
privileged operation on every operating system.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_NAMES = {PROTO_TCP: "TCP", PROTO_UDP: "UDP"}

# Ports that identify the server end of a conversation.
WELL_KNOWN = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 9200, 11211, 27017,
}


def parse_ipv4(data: bytes) -> tuple | None:
    """
    Pull the five-tuple and payload size out of an IPv4 packet.

    Returns (src_ip, src_port, dst_ip, dst_port, protocol_name, total_bytes)
    or None if this is not IPv4 TCP/UDP.
    """
    if len(data) < 20:
        return None

    version_ihl = data[0]
    if (version_ihl >> 4) != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None

    total_length = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    if protocol not in PROTO_NAMES:
        return None

    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    transport = data[ihl : ihl + 4]
    if len(transport) < 4:
        return None
    src_port, dst_port = struct.unpack("!HH", transport)

    # Trust the header length where it looks sane; some drivers pad the buffer.
    size = total_length if 20 <= total_length <= len(data) else len(data)
    return src_ip, src_port, dst_ip, dst_port, PROTO_NAMES[protocol], size


def parse_ethernet(frame: bytes) -> bytes | None:
    """Strip an Ethernet header and return the IPv4 payload, if any."""
    if len(frame) < ETH_HEADER_LEN:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None
    return frame[ETH_HEADER_LEN:]


def server_side(port_a: int, port_b: int) -> bool:
    """
    True if port_a is the more likely server port of the pair.

    Used to orient each conversation as client -> server, so `dest_port` is the
    service being contacted and `bytes_out` is what the client pushed. Getting
    this the wrong way round would invert the exfiltration ratio.
    """
    a_known, b_known = port_a in WELL_KNOWN, port_b in WELL_KNOWN
    if a_known != b_known:
        return a_known
    a_priv, b_priv = port_a < 1024, port_b < 1024
    if a_priv != b_priv:
        return a_priv
    return port_a <= port_b


# ---------------------------------------------------------------------------
# Flow aggregation
# ---------------------------------------------------------------------------


class FlowAggregator:
    """
    Collapses individual packets into directional byte counts, then pairs the
    two directions of each conversation into one flow record.

    This is what a real NetFlow exporter does. The analyser never sees packets,
    only these summaries - no payloads, no message contents.
    """

    def __init__(self, exclude_ips: set[str] | None = None) -> None:
        self._bytes: dict[tuple, int] = defaultdict(int)
        self._packets: dict[tuple, int] = defaultdict(int)
        self._first_seen: dict[tuple, float] = {}
        self._lock = threading.Lock()
        self._exclude = exclude_ips or set()
        self.packets_seen = 0
        self.packets_ignored = 0

    def add_packet(self, parsed: tuple, observed_at: float) -> None:
        """
        `observed_at` is when the packet actually crossed the wire - the capture
        clock for live traffic, or the recorded timestamp for a replayed file.
        Using our own processing time here instead would squash a replayed
        capture into a single instant and destroy the timing the rules depend on.
        """
        src_ip, src_port, dst_ip, dst_port, proto, size = parsed
        self.packets_seen += 1

        # Never account for our own traffic to the analyser; that would create a
        # feedback loop where reporting generates more to report.
        if src_ip in self._exclude or dst_ip in self._exclude:
            self.packets_ignored += 1
            return

        key = (src_ip, src_port, dst_ip, dst_port, proto)
        with self._lock:
            self._bytes[key] += size
            self._packets[key] += 1
            existing = self._first_seen.get(key)
            if existing is None or observed_at < existing:
                self._first_seen[key] = observed_at

    def drain(self) -> list[dict]:
        """Take everything accumulated so far and return it as flow records."""
        with self._lock:
            byte_counts = dict(self._bytes)
            first_seen = dict(self._first_seen)
            self._bytes.clear()
            self._packets.clear()
            self._first_seen.clear()

        records: list[dict] = []
        handled: set[tuple] = set()

        for key, forward_bytes in byte_counts.items():
            if key in handled:
                continue
            src_ip, src_port, dst_ip, dst_port, proto = key
            reverse = (dst_ip, dst_port, src_ip, src_port, proto)
            reverse_bytes = byte_counts.get(reverse, 0)
            handled.add(key)
            handled.add(reverse)

            if server_side(dst_port, src_port):
                client_ip, server_ip, server_port = src_ip, dst_ip, dst_port
                bytes_out, bytes_in = forward_bytes, reverse_bytes
            else:
                client_ip, server_ip, server_port = dst_ip, src_ip, src_port
                bytes_out, bytes_in = reverse_bytes, forward_bytes

            own = first_seen.get(key)
            other = first_seen.get(reverse)
            candidates = [v for v in (own, other) if v is not None]
            started = min(candidates) if candidates else time.time()
            records.append(
                {
                    "timestamp": datetime.fromtimestamp(started, timezone.utc)
                    .isoformat(timespec="milliseconds"),
                    "source_ip": client_ip,
                    "dest_ip": server_ip,
                    "dest_port": server_port,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "protocol": proto,
                    "source": "live",
                }
            )

        return records


# ---------------------------------------------------------------------------
# Capture backends
# ---------------------------------------------------------------------------


def is_elevated() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def local_ipv4_addresses() -> list[str]:
    """Every IPv4 address this host owns, best guess first."""
    found: list[str] = []
    try:
        primary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        primary.connect(("8.8.8.8", 80))  # no packets sent; just picks a route
        found.append(primary.getsockname()[0])
        primary.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr not in found:
                found.append(addr)
    except Exception:
        pass
    return found or ["127.0.0.1"]


class WindowsCapture:
    """Promiscuous capture via raw socket + SIO_RCVALL. Needs Administrator."""

    strips_ethernet = False

    def __init__(self, bind_ip: str) -> None:
        self.bind_ip = bind_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind((bind_ip, 0))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.sock.settimeout(1.0)

    def read(self) -> tuple[float, bytes] | None:
        try:
            return time.time(), self.sock.recvfrom(65535)[0]
        except socket.timeout:
            return None

    def close(self) -> None:
        try:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        self.sock.close()


class LinuxCapture:
    """Promiscuous capture via AF_PACKET. Needs root or CAP_NET_RAW."""

    strips_ethernet = True

    def __init__(self, interface: str | None = None) -> None:
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface:
            self.sock.bind((interface, 0))
        self.sock.settimeout(1.0)
        self.bind_ip = interface or "any"

    def read(self) -> tuple[float, bytes] | None:
        try:
            return time.time(), self.sock.recvfrom(65535)[0]
        except socket.timeout:
            return None

    def close(self) -> None:
        self.sock.close()


class PcapFileCapture:
    """
    Replays a real .pcap file. No privileges required.

    Useful when live capture is not permitted: the packets are still genuine
    captured traffic, just recorded earlier.
    """

    def __init__(self, path: str, speed: float = 1.0) -> None:
        self.path = path
        self.speed = speed
        self.handle = open(path, "rb")

        header = self.handle.read(24)
        if len(header) < 24:
            raise ValueError("file is too short to be a pcap")

        magic = header[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self.endian = "<"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("this is a pcapng file; save as pcap in Wireshark")
        else:
            raise ValueError(f"not a pcap file (magic {magic!r})")

        self.nanosecond = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
        self.linktype = struct.unpack(self.endian + "I", header[20:24])[0]
        # 1 = Ethernet, 101/12/14 = raw IP
        self.strips_ethernet = self.linktype == 1
        if self.linktype not in (1, 12, 14, 101, 228):
            raise ValueError(f"unsupported pcap link type {self.linktype}")
        self.bind_ip = os.path.basename(path)

    def read(self) -> tuple[float, bytes] | None:
        header = self.handle.read(16)
        if len(header) < 16:
            return None
        sec, frac, incl_len, _orig_len = struct.unpack(self.endian + "IIII", header)
        payload = self.handle.read(incl_len)
        if not payload:
            return None
        # The capture's own recorded time, so replay preserves real spacing.
        divisor = 1_000_000_000 if self.nanosecond else 1_000_000
        return sec + frac / divisor, payload

    def close(self) -> None:
        self.handle.close()


# ---------------------------------------------------------------------------
# Shipping
# ---------------------------------------------------------------------------


class Shipper:
    def __init__(self, backend: str, host_label: str, interface: str) -> None:
        self.url = backend.rstrip("/") + "/api/ingest"
        self.host_label = host_label
        self.interface = interface
        self.sent = 0
        self.alerts = 0
        self.failures = 0

    def send(self, flows: list[dict]) -> dict | None:
        body = json.dumps(
            {"host": self.host_label, "interface": self.interface, "flows": flows}
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.loads(response.read())
            self.sent += len(flows)
            self.alerts += result.get("alerts_raised", 0)
            return result
        except urllib.error.HTTPError as e:
            self.failures += 1
            print(f"  ! analyser rejected batch: HTTP {e.code} {e.read()[:120]!r}")
        except Exception as e:
            self.failures += 1
            print(f"  ! could not reach analyser: {type(e).__name__}: {str(e)[:100]}")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_capture(args) -> object:
    if args.pcap:
        return PcapFileCapture(args.pcap)

    if not is_elevated():
        print("ERROR: live capture needs elevated privileges.")
        if os.name == "nt":
            print("  Right-click Windows PowerShell -> 'Run as Administrator', then retry.")
            print("  Or capture to a file in Wireshark and replay it with --pcap file.pcap")
        else:
            print("  Re-run with sudo, or replay a capture with --pcap file.pcap")
        sys.exit(2)

    if os.name == "nt":
        bind_ip = args.interface or local_ipv4_addresses()[0]
        print(f"  binding raw socket to {bind_ip}")
        return WindowsCapture(bind_ip)

    return LinuxCapture(args.interface)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture real network flows and feed them to the Passive Threat Detector."
    )
    parser.add_argument("--backend", default="http://127.0.0.1:8000",
                        help="analyser base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--interface", default=None,
                        help="Windows: local IP to bind. Linux: interface name.")
    parser.add_argument("--pcap", default=None,
                        help="replay a .pcap file instead of live capture")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between batches (default: 2.0)")
    parser.add_argument("--duration", type=float, default=0,
                        help="stop after N seconds (0 = run until Ctrl+C)")
    parser.add_argument("--list", action="store_true",
                        help="list local IPv4 addresses and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="capture and print flows without sending them")
    args = parser.parse_args()

    if args.list:
        print("Local IPv4 addresses (use one with --interface):")
        for addr in local_ipv4_addresses():
            print(f"  {addr}")
        print(f"\nElevated: {is_elevated()}")
        return

    # Resolve the analyser's own address so we can exclude our own reporting
    # traffic from the capture.
    exclude: set[str] = {"127.0.0.1"}
    backend_host = args.backend.split("//")[-1].split("/")[0].split(":")[0]
    try:
        for info in socket.getaddrinfo(backend_host, None, socket.AF_INET):
            exclude.add(info[4][0])
    except Exception:
        pass

    print("=" * 66)
    print(" Passive Threat Detector - live capture sensor")
    print("=" * 66)
    print(f"  mode     : {'pcap replay' if args.pcap else 'live interface capture'}")
    print(f"  analyser : {args.backend}")
    print(f"  excluded : {', '.join(sorted(exclude))}  (own reporting traffic)")

    capture = build_capture(args)
    strips_ethernet = getattr(capture, "strips_ethernet", False)
    aggregator = FlowAggregator(exclude_ips=exclude)
    shipper = Shipper(args.backend, socket.gethostname(), str(getattr(capture, "bind_ip", "?")))

    print(f"  source   : {shipper.interface}")
    print("-" * 66)
    print("  Capturing. Generate traffic to see flows appear. Ctrl+C to stop.")
    print("  Tip: uploading a large file should trip the exfiltration rule.")
    print("-" * 66)

    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            try:
                item = capture.read()
            except Exception as e:
                print(f"  ! capture error: {type(e).__name__}: {e}")
                break
            if item is None:
                if args.pcap:
                    stop.set()
                    break
                continue
            observed_at, raw = item
            payload = parse_ethernet(raw) if strips_ethernet else raw
            if payload is None:
                continue
            parsed = parse_ipv4(payload)
            if parsed:
                aggregator.add_packet(parsed, observed_at)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    started = time.time()
    try:
        while not stop.is_set():
            time.sleep(args.interval)
            flows = aggregator.drain()
            elapsed = time.time() - started

            if flows:
                if args.dry_run:
                    for f in flows[:8]:
                        print(f"    {f['source_ip']}:{'':<1} -> {f['dest_ip']}:{f['dest_port']}"
                              f" {f['protocol']}  out={f['bytes_out']} in={f['bytes_in']}")
                    result = None
                else:
                    result = shipper.send(flows)
                raised = result.get("alerts_raised", 0) if result else 0
                flag = f"  <-- {raised} ALERT(S)" if raised else ""
                print(f"  [{elapsed:6.1f}s] packets={aggregator.packets_seen:6d}"
                      f"  flows sent={len(flows):3d}  total={shipper.sent:5d}{flag}")
            else:
                print(f"  [{elapsed:6.1f}s] packets={aggregator.packets_seen:6d}"
                      f"  no new flows")

            if args.duration and elapsed >= args.duration:
                break
    except KeyboardInterrupt:
        print("\n  stopping...")
    finally:
        stop.set()
        remaining = aggregator.drain()
        if remaining and not args.dry_run:
            shipper.send(remaining)
        capture.close()

    print("-" * 66)
    print(f"  packets examined : {aggregator.packets_seen}")
    print(f"  packets excluded : {aggregator.packets_ignored} (traffic to the analyser)")
    print(f"  flows shipped    : {shipper.sent}")
    print(f"  alerts raised    : {shipper.alerts}")
    print(f"  failed batches   : {shipper.failures}")
    print("=" * 66)


if __name__ == "__main__":
    main()
