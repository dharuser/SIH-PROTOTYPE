"""
Passive Threat Detector - live capture sensor.

Reads REAL network activity from this machine, summarises it into flow records,
and ships them to the analyser over HTTP.

Why this exists as a separate program
-------------------------------------
This is the piece that makes the project real rather than a simulation. It also
mirrors the architecture it is modelling:

    [ monitored network ] --> sensor --> (one direction only) --> analyser

The sensor reads traffic and sends summaries out. It never injects, replies to,
or modifies traffic, and the analyser has no channel back to it. That is exactly
the constraint a hardware data diode imposes.

Capture modes
-------------
  packet      raw packet capture from a live interface   (needs Administrator/root)
              full fidelity: endpoints, ports, timing AND byte volumes
  connection  OS connection table polling                (NO privileges needed)
              real endpoints, ports and owning process, but no byte volumes
              (the OS does not expose per-connection counters to an
              unprivileged process) and it SAMPLES, so connections that open
              and close between polls are missed. Good for proving the data is
              real; not a complete view.
  pcap        replay a real .pcap file                   (NO privileges needed)
              full fidelity, from traffic recorded earlier

Being explicit about that limitation matters more than papering over it. The
alternative would be inventing byte counts, which would make every exfiltration
detection meaningless.

Usage
-----
  python agent.py                        # auto-selects the best available mode
  python agent.py --mode connection      # force no-privilege mode
  python agent.py --pcap capture.pcap
  python agent.py --list

Optional dependency: psutil, for process attribution and connection mode.
  pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # optional: only needed for connection mode / process names
    psutil = None


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
    465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 9200, 11211, 27017,
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


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# Enrichment: which program owns a connection, and what is that IP called
# ---------------------------------------------------------------------------


class ProcessResolver:
    """
    Maps a local port to the program that owns it.

    Turns "10.156.151.62 sent 40 MB out" into "msedge.exe sent 40 MB out", which
    is the difference between an alert an analyst can act on and one they cannot.
    Rebuilt on a short TTL because ports are reused constantly.
    """

    def __init__(self, ttl: float = 3.0) -> None:
        self.ttl = ttl
        self._by_port: dict[int, str] = {}
        self._refreshed = 0.0
        self.available = psutil is not None

    def refresh(self, force: bool = False) -> None:
        if not self.available:
            return
        if not force and (time.time() - self._refreshed) < self.ttl:
            return
        mapping: dict[int, str] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.laddr or not conn.pid:
                    continue
                try:
                    mapping[conn.laddr.port] = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            return
        self._by_port = mapping
        self._refreshed = time.time()

    def lookup(self, *ports: int) -> str | None:
        for port in ports:
            name = self._by_port.get(port)
            if name:
                return name
        return None


class DnsResolver:
    """
    Best-effort reverse DNS, resolved on a background thread.

    Reverse lookups can block for seconds. Doing them inline would stall the
    capture loop and lose packets, so addresses are queued and answered later;
    flows are enriched only once a name is already cached. A hostname is a nice
    detail, never worth dropping traffic for.
    """

    def __init__(self, max_entries: int = 4000) -> None:
        self._cache: dict[str, str | None] = {}
        self._queue: queue.Queue[str] = queue.Queue(maxsize=1000)
        self._max = max_entries
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._cache[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                self._cache[ip] = None

    def lookup(self, ip: str) -> str | None:
        if ip in self._cache:
            return self._cache[ip]
        if len(self._cache) < self._max:
            try:
                self._queue.put_nowait(ip)
            except queue.Full:
                pass
        return None

    @property
    def resolved(self) -> int:
        return sum(1 for v in self._cache.values() if v)

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# Flow aggregation (packet and pcap modes)
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
            existing = self._first_seen.get(key)
            if existing is None or observed_at < existing:
                self._first_seen[key] = observed_at

    def drain(self) -> list[dict]:
        """Take everything accumulated so far and return it as flow records."""
        with self._lock:
            byte_counts = dict(self._bytes)
            first_seen = dict(self._first_seen)
            self._bytes.clear()
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
                client_ip, client_port = src_ip, src_port
                server_ip, server_port = dst_ip, dst_port
                bytes_out, bytes_in = forward_bytes, reverse_bytes
            else:
                client_ip, client_port = dst_ip, dst_port
                server_ip, server_port = src_ip, src_port
                bytes_out, bytes_in = reverse_bytes, forward_bytes

            own = first_seen.get(key)
            other = first_seen.get(reverse)
            candidates = [v for v in (own, other) if v is not None]
            started = min(candidates) if candidates else time.time()

            records.append({
                "timestamp": iso(started),
                "source_ip": client_ip,
                "dest_ip": server_ip,
                "dest_port": server_port,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "protocol": proto,
                "source": "live",
                "_local_ports": (client_port, server_port),
            })

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
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))  # no packets sent; just picks a route
        found.append(probe.getsockname()[0])
        probe.close()
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
    measures_bytes = True

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
    measures_bytes = True

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
    """Replays a real .pcap file. No privileges required."""

    measures_bytes = True

    def __init__(self, path: str) -> None:
        self.path = path
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
        divisor = 1_000_000_000 if self.nanosecond else 1_000_000
        return sec + frac / divisor, payload

    def close(self) -> None:
        self.handle.close()


class ConnectionPoller:
    """
    Reads the operating system's own connection table. No privileges required.

    Every newly-observed connection becomes one flow record with genuine
    endpoints, ports, protocol and owning process. What it CANNOT provide is byte
    volume: neither Windows nor Linux exposes per-connection counters to an
    unprivileged process. Those fields are therefore reported as zero rather than
    estimated, which means the exfiltration rule stays silent in this mode
    instead of firing on numbers nobody measured.
    """

    measures_bytes = False

    def __init__(self, exclude_ips: set[str], resolver: ProcessResolver) -> None:
        if psutil is None:
            raise RuntimeError("connection mode requires psutil (pip install psutil)")
        self._seen: dict[tuple, float] = {}
        self._exclude = exclude_ips
        self._resolver = resolver
        self._locals = set(local_ipv4_addresses())
        self.bind_ip = "OS connection table"
        self.connections_seen = 0

    def poll(self) -> list[dict]:
        now = time.time()
        records: list[dict] = []

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return records

        self._resolver.refresh()

        for conn in connections:
            if not conn.raddr or not conn.laddr:
                continue
            local_ip, local_port = conn.laddr.ip, conn.laddr.port
            remote_ip, remote_port = conn.raddr.ip, conn.raddr.port

            if remote_ip in self._exclude or local_ip in self._exclude:
                continue
            if remote_ip.startswith("127.") or remote_ip == "::1":
                continue

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            key = (local_ip, local_port, remote_ip, remote_port, proto)

            # Only report a connection once, when first observed. Repeat
            # check-ins to the same host open new connections, which is exactly
            # the signal the beaconing rule needs.
            if key in self._seen:
                continue
            self._seen[key] = now
            self.connections_seen += 1

            process = None
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid).name()
                except Exception:
                    process = None

            if server_side(remote_port, local_port):
                client_ip, server_ip, server_port = local_ip, remote_ip, remote_port
            else:
                client_ip, server_ip, server_port = remote_ip, local_ip, local_port

            records.append({
                "timestamp": iso(now),
                "source_ip": client_ip,
                "dest_ip": server_ip,
                "dest_port": server_port,
                "bytes_in": 0,
                "bytes_out": 0,
                "protocol": proto,
                "source": "live",
                "process": process,
                "_local_ports": (local_port,),
            })

        # Forget connections that have closed, so a later reconnection to the
        # same host counts as a fresh check-in.
        live_keys = set()
        for conn in connections:
            if conn.raddr and conn.laddr:
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                live_keys.add(
                    (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port, proto)
                )
        for key in list(self._seen):
            if key not in live_keys:
                del self._seen[key]

        return records

    def close(self) -> None:
        pass


class ThroughputMeter:
    """
    Real interface-level byte counters.

    Deliberately kept separate from flow records. These totals are genuine but
    cannot be attributed to individual connections, so they are reported as
    overall throughput rather than folded into any flow's byte fields.
    """

    def __init__(self) -> None:
        self.available = psutil is not None
        self._last: tuple[float, int, int] | None = None

    def sample(self) -> dict | None:
        if not self.available:
            return None
        try:
            counters = psutil.net_io_counters()
        except Exception:
            return None
        now = time.time()
        current = (now, counters.bytes_sent, counters.bytes_recv)
        if self._last is None:
            self._last = current
            return None
        elapsed = now - self._last[0]
        if elapsed <= 0:
            return None
        result = {
            "bytes_sent_per_sec": int((current[1] - self._last[1]) / elapsed),
            "bytes_recv_per_sec": int((current[2] - self._last[2]) / elapsed),
            "total_sent": current[1],
            "total_recv": current[2],
        }
        self._last = current
        return result


# ---------------------------------------------------------------------------
# Shipping
# ---------------------------------------------------------------------------


class Shipper:
    def __init__(self, backend: str, host_label: str, interface: str, mode: str) -> None:
        self.url = backend.rstrip("/") + "/api/ingest"
        self.host_label = host_label
        self.interface = interface
        self.mode = mode
        self.sent = 0
        self.alerts = 0
        self.failures = 0

    def send(self, flows: list[dict], throughput: dict | None = None) -> dict | None:
        payload = {
            "host": self.host_label,
            "interface": f"{self.interface} [{self.mode}]",
            "flows": flows,
        }
        if throughput:
            payload["throughput"] = throughput

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
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
            print(f"  ! analyser rejected batch: HTTP {e.code} {e.read()[:150]!r}")
        except Exception as e:
            self.failures += 1
            print(f"  ! could not reach analyser: {type(e).__name__}: {str(e)[:100]}")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def choose_mode(args) -> str:
    if args.pcap:
        return "pcap"
    if args.mode != "auto":
        return args.mode
    if is_elevated():
        return "packet"
    if psutil is not None:
        return "connection"
    return "packet"  # will fail with a clear privilege message


def build_capture(mode: str, args, exclude: set[str], resolver: ProcessResolver):
    if mode == "pcap":
        return PcapFileCapture(args.pcap)

    if mode == "connection":
        return ConnectionPoller(exclude, resolver)

    if not is_elevated():
        print("ERROR: packet capture needs elevated privileges.")
        if os.name == "nt":
            print("  Right-click PowerShell -> 'Run as Administrator', then retry.")
        else:
            print("  Re-run with sudo.")
        print("  No admin? Two options that need no privileges at all:")
        print("    python agent.py --mode connection      (real connections + process names)")
        print("    python agent.py --pcap capture.pcap    (replay a Wireshark capture)")
        sys.exit(2)

    if os.name == "nt":
        bind_ip = args.interface or local_ipv4_addresses()[0]
        print(f"  binding raw socket to {bind_ip}")
        return WindowsCapture(bind_ip)

    return LinuxCapture(args.interface)


def enrich(records: list[dict], resolver: ProcessResolver, dns: DnsResolver) -> None:
    """Attach the owning program and a hostname where we can, in place."""
    resolver.refresh()
    for record in records:
        ports = record.pop("_local_ports", ())
        if not record.get("process"):
            record["process"] = resolver.lookup(*ports)
        record["hostname"] = dns.lookup(record["dest_ip"])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture real network activity and feed it to the Passive Threat Detector."
    )
    parser.add_argument("--backend", default="http://127.0.0.1:8000",
                        help="analyser base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--mode", default="auto",
                        choices=["auto", "packet", "connection"],
                        help="capture mode (default: auto)")
    parser.add_argument("--interface", default=None,
                        help="Windows: local IP to bind. Linux: interface name.")
    parser.add_argument("--pcap", default=None,
                        help="replay a .pcap file instead of live capture")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between batches (default: 2.0)")
    parser.add_argument("--duration", type=float, default=0,
                        help="stop after N seconds (0 = run until Ctrl+C)")
    parser.add_argument("--list", action="store_true",
                        help="show capabilities and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="capture and print flows without sending them")
    args = parser.parse_args()

    if args.list:
        print("Local IPv4 addresses (use one with --interface):")
        for addr in local_ipv4_addresses():
            print(f"  {addr}")
        print(f"\nElevated (packet capture available) : {is_elevated()}")
        print(f"psutil present (connection mode)    : {psutil is not None}")
        print(f"Mode that would be auto-selected    : {choose_mode(args)}")
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

    mode = choose_mode(args)
    resolver = ProcessResolver()
    dns = DnsResolver()
    throughput = ThroughputMeter()

    print("=" * 70)
    print(" Passive Threat Detector - live capture sensor")
    print("=" * 70)
    print(f"  mode      : {mode}")
    print(f"  analyser  : {args.backend}")
    print(f"  excluded  : {', '.join(sorted(exclude))}  (own reporting traffic)")

    capture = build_capture(mode, args, exclude, resolver)
    measures_bytes = getattr(capture, "measures_bytes", True)

    print(f"  source    : {getattr(capture, 'bind_ip', '?')}")
    print(f"  byte volumes measurable : {measures_bytes}")
    if not measures_bytes:
        print("    NOTE: this mode samples the OS connection table, so it")
        print("    (a) cannot measure byte volumes -> exfiltration rule inactive")
        print("    (b) may miss connections that open and close between polls")
        print("    Real endpoints, ports and process names are accurate.")
        print("    Use --mode packet (as Administrator) for complete capture.")
    print("-" * 70)
    print("  Ctrl+C to stop.")
    if measures_bytes and mode != "pcap":
        print("  Tip: upload a large file to trip the exfiltration rule.")
    print("-" * 70)

    shipper = Shipper(
        args.backend, socket.gethostname(), str(getattr(capture, "bind_ip", "?")), mode
    )
    stop = threading.Event()
    aggregator: FlowAggregator | None = None
    thread: threading.Thread | None = None

    if mode in ("packet", "pcap"):
        aggregator = FlowAggregator(exclude_ips=exclude)
        strips_ethernet = getattr(capture, "strips_ethernet", False)

        def reader() -> None:
            while not stop.is_set():
                try:
                    item = capture.read()
                except Exception as e:
                    print(f"  ! capture error: {type(e).__name__}: {e}")
                    break
                if item is None:
                    if mode == "pcap":
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
            elapsed = time.time() - started

            flows = aggregator.drain() if aggregator else capture.poll()
            enrich(flows, resolver, dns)
            tp = throughput.sample()

            if flows:
                if args.dry_run:
                    for f in flows[:8]:
                        proc = f.get("process") or "?"
                        host = f.get("hostname") or ""
                        print(f"    {f['source_ip']} -> {f['dest_ip']}:{f['dest_port']} "
                              f"{f['protocol']} out={f['bytes_out']} in={f['bytes_in']} "
                              f"[{proc}] {host}")
                    result = None
                else:
                    result = shipper.send(flows, tp)
                raised = result.get("alerts_raised", 0) if result else 0
                flag = f"  <-- {raised} ALERT(S)" if raised else ""
                seen = (aggregator.packets_seen if aggregator
                        else capture.connections_seen)
                unit = "packets" if aggregator else "conns"
                rate = ""
                if tp:
                    rate = (f"  net {tp['bytes_recv_per_sec']//1024:>5d}KB/s in"
                            f" {tp['bytes_sent_per_sec']//1024:>5d}KB/s out")
                print(f"  [{elapsed:6.1f}s] {unit}={seen:6d}  flows={len(flows):3d}"
                      f"  total={shipper.sent:5d}{rate}{flag}")
            else:
                print(f"  [{elapsed:6.1f}s] no new flows")

            if args.duration and elapsed >= args.duration:
                break
    except KeyboardInterrupt:
        print("\n  stopping...")
    finally:
        stop.set()
        if aggregator:
            remaining = aggregator.drain()
            enrich(remaining, resolver, dns)
            if remaining and not args.dry_run:
                shipper.send(remaining)
        capture.close()
        dns.stop()

    print("-" * 70)
    if aggregator:
        print(f"  packets examined  : {aggregator.packets_seen}")
        print(f"  packets excluded  : {aggregator.packets_ignored} (analyser traffic)")
    else:
        print(f"  connections seen  : {capture.connections_seen}")
    print(f"  flows shipped     : {shipper.sent}")
    print(f"  alerts raised     : {shipper.alerts}")
    print(f"  hostnames resolved: {dns.resolved}")
    print(f"  failed batches    : {shipper.failures}")
    print("=" * 70)


if __name__ == "__main__":
    main()
