#!/usr/bin/env python3
"""portprobe — Fast TCP port scanner and service checker.

Usage:
    portprobe scan HOST [--ports RANGE] [--timeout SECS] [--workers N] [--json]
    portprobe check HOST:PORT [HOST:PORT...] [--timeout SECS] [--json]
    portprobe common HOST [--timeout SECS] [--json]

Examples:
    portprobe scan 192.168.1.1 --ports 1-1024
    portprobe check localhost:8080 localhost:5432 localhost:6379
    portprobe common myserver.local
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3000: "Dev", 3306: "MySQL", 3389: "RDP", 4000: "Dev",
    5000: "Dev", 5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    6379: "Redis", 6443: "K8s-API", 8000: "Dev", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "ES-Transport", 11211: "Memcached",
    15672: "RabbitMQ", 18789: "OpenClaw", 27017: "MongoDB",
    50051: "gRPC",
}


@dataclass
class PortResult:
    host: str
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    latency_ms: float = 0
    error: str = ""


@dataclass
class ScanResult:
    host: str
    ip: str = ""
    total_scanned: int = 0
    open_ports: int = 0
    scan_time_ms: float = 0
    ports: list = field(default_factory=list)


def probe_port(host: str, port: int, timeout: float = 2, grab_banner: bool = True) -> PortResult:
    """Check if a TCP port is open and optionally grab banner."""
    result = PortResult(host=host, port=port, open=False)
    result.service = COMMON_PORTS.get(port, "")

    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        result.open = True
        result.latency_ms = (time.monotonic() - start) * 1000

        if grab_banner:
            try:
                sock.settimeout(1)
                # Send empty line for protocols that need prompting
                if port in (80, 8080, 8000, 3000, 4000, 5000, 8443, 443):
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                if banner:
                    # Clean up banner — first line only
                    result.banner = banner.split("\n")[0][:80]
            except (socket.timeout, OSError):
                pass

    except ConnectionRefusedError:
        result.error = "refused"
    except socket.timeout:
        result.error = "timeout"
    except OSError as e:
        result.error = str(e)[:40]
    finally:
        sock.close()

    if not result.latency_ms:
        result.latency_ms = (time.monotonic() - start) * 1000

    return result


def resolve_host(host: str) -> str:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""


def parse_ports(spec: str) -> list[int]:
    """Parse port specification like '80,443,8000-8100'."""
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# Colors
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def format_result(result: ScanResult, show_closed: bool = False) -> str:
    lines = []
    lines.append(f"\n{BOLD}{result.host}{RESET} ({result.ip})")
    lines.append(f"{DIM}Scanned {result.total_scanned} ports in {result.scan_time_ms:.0f}ms{RESET}\n")

    open_ports = [p for p in result.ports if p.open]
    if not open_ports:
        lines.append(f"  {DIM}No open ports found{RESET}")
    else:
        lines.append(f"  {'PORT':>7s}  {'STATE':8s}  {'SERVICE':15s}  {'LATENCY':>8s}  BANNER")
        lines.append(f"  {'─' * 65}")
        for p in open_ports:
            svc = p.service or "unknown"
            lat = f"{p.latency_ms:.0f}ms"
            banner = p.banner[:40] if p.banner else ""
            lines.append(f"  {GREEN}{p.port:>5d}/tcp  {'open':8s}  {svc:15s}  {lat:>8s}{RESET}  {DIM}{banner}{RESET}")

    lines.append(f"\n{GREEN}{result.open_ports} open{RESET} / {result.total_scanned} scanned")
    return "\n".join(lines)


def scan_host(host: str, ports: list[int], timeout: float = 2,
              workers: int = 50, grab_banner: bool = True) -> ScanResult:
    """Scan multiple ports on a host."""
    result = ScanResult(host=host)
    result.ip = resolve_host(host)
    if not result.ip:
        result.ip = "unresolved"

    start = time.monotonic()
    result.total_scanned = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_port, host, p, timeout, grab_banner): p
            for p in ports
        }
        for future in concurrent.futures.as_completed(futures):
            pr = future.result()
            if pr.open:
                result.ports.append(pr)
                result.open_ports += 1
                # Show progress for open ports
                svc = pr.service or "unknown"
                print(f"  {GREEN}Found: {pr.port}/tcp ({svc}){RESET}", file=sys.stderr)

    result.ports.sort(key=lambda p: p.port)
    result.scan_time_ms = (time.monotonic() - start) * 1000
    return result


def main():
    parser = argparse.ArgumentParser(prog="portprobe", description="Fast TCP port scanner and service checker")
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Scan port range on a host")
    scan_p.add_argument("host", help="Target host")
    scan_p.add_argument("--ports", "-p", default="1-1024", help="Port range (e.g., 1-1024, 80,443,8080)")
    scan_p.add_argument("--timeout", "-t", type=float, default=1, help="Connection timeout (default: 1s)")
    scan_p.add_argument("--workers", "-w", type=int, default=100, help="Concurrent workers (default: 100)")
    scan_p.add_argument("--json", "-j", action="store_true")
    scan_p.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")

    # check
    check_p = sub.add_parser("check", help="Check specific host:port pairs")
    check_p.add_argument("targets", nargs="+", help="host:port pairs")
    check_p.add_argument("--timeout", "-t", type=float, default=2)
    check_p.add_argument("--json", "-j", action="store_true")

    # common
    common_p = sub.add_parser("common", help="Scan common service ports")
    common_p.add_argument("host", help="Target host")
    common_p.add_argument("--timeout", "-t", type=float, default=1)
    common_p.add_argument("--json", "-j", action="store_true")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        ports = parse_ports(args.ports)
        print(f"Scanning {args.host} ({len(ports)} ports)...", file=sys.stderr)
        result = scan_host(args.host, ports, args.timeout, args.workers, not args.no_banner)

    elif args.command == "check":
        results = []
        for target in args.targets:
            if ":" not in target:
                print(f"Invalid target: {target} (expected host:port)", file=sys.stderr)
                continue
            host, port_str = target.rsplit(":", 1)
            pr = probe_port(host, int(port_str), args.timeout)
            status = f"{GREEN}OPEN{RESET}" if pr.open else f"{RED}CLOSED{RESET}"
            svc = f" ({pr.service})" if pr.service else ""
            lat = f" {pr.latency_ms:.0f}ms" if pr.open else ""
            banner = f" — {pr.banner}" if pr.banner else ""
            results.append(pr)
            if not args.json:
                print(f"  {target}{svc}: {status}{lat}{banner}")

        if args.json:
            print(json.dumps([asdict(r) for r in results], indent=2))
        sys.exit(0 if all(r.open for r in results) else 1)

    elif args.command == "common":
        ports = sorted(COMMON_PORTS.keys())
        print(f"Scanning {args.host} ({len(ports)} common ports)...", file=sys.stderr)
        result = scan_host(args.host, ports, args.timeout, workers=50)

    if args.command in ("scan", "common"):
        if args.json:
            print(json.dumps(asdict(result), indent=2, default=str))
        else:
            print(format_result(result))
        sys.exit(0 if result.open_ports > 0 else 1)


if __name__ == "__main__":
    main()
