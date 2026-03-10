# portprobe 🔍

Fast TCP port scanner and service checker. Scan ranges, check specific endpoints, or probe common service ports. With banner grabbing.

## Features

- **Fast concurrent scanning** — 100 workers by default, scans 1024 ports in seconds
- **Banner grabbing** — identifies HTTP servers, SSH versions, etc.
- **Common port knowledge** — knows 40+ well-known services (SSH, HTTP, Redis, PostgreSQL, etc.)
- **Three modes** — range scan, targeted check, or common ports
- **JSON output** — machine-readable for CI/monitoring
- **Zero deps** — pure Python 3.10+

## Usage

### Scan a port range

```bash
# Scan first 1024 ports
python3 portprobe.py scan 192.168.1.1

# Custom range
python3 portprobe.py scan myserver.local --ports 8000-9000

# Specific ports
python3 portprobe.py scan host.local --ports 80,443,8080,3000
```

### Check specific endpoints

```bash
# Check if services are reachable
python3 portprobe.py check localhost:8080 db.local:5432 cache:6379

# Returns exit code 0 only if ALL ports are open
```

### Scan common service ports

```bash
# Quick check for known services (SSH, HTTP, databases, etc.)
python3 portprobe.py common myserver.local
```

## Output

```
localhost (127.0.0.1)
Scanned 40 ports in 1008ms

     PORT  STATE     SERVICE           LATENCY  BANNER
  ─────────────────────────────────────────────────────────────────
   5000/tcp  open      Dev                   3ms  HTTP/1.1 200 OK
  18789/tcp  open      OpenClaw              2ms

2 open / 40 scanned
```

## Options

| Flag | Description |
|------|-------------|
| `--ports, -p` | Port range (default: 1-1024) |
| `--timeout, -t` | Connection timeout (default: 1s scan, 2s check) |
| `--workers, -w` | Concurrent workers (default: 100) |
| `--no-banner` | Skip banner grabbing (faster) |
| `--json, -j` | JSON output |

## Exit codes

- `0` — open ports found (scan/common) or all targets open (check)
- `1` — no open ports or some targets closed

## License

MIT
