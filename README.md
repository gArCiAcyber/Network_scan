# hylianscan

[![tests](https://github.com/gArCiAcyber/Network_scan/actions/workflows/tests.yml/badge.svg)](https://github.com/gArCiAcyber/Network_scan/actions/workflows/tests.yml)

`hylianscan` is a Python 3 reconnaissance and networking lab tool built for authorized targets, Kali Linux workflows, and practical study of offensive security automation.

The current release version is `v0.9`.

## Scope

Use this project only in your own lab, authorized networks, or explicit pentest scopes.

## Current Capabilities

### TCP Port Scanning

- Flexible Targeting: Resolves domains to IPv4 addresses or accepts direct IPs.
- High Performance: Multi-threaded TCP scanning utilizing `ThreadPoolExecutor` and `socket.connect_ex()`.
- Scan Pacing: Optional `--max-rate` control limits how quickly new TCP connection attempts are started and is shown in the effective scan configuration.
- Custom Port Selection: Supports comma-separated lists (`-p 80,443`), explicit ranges (`-p 1-1000`), top-port presets (`--top-ports`), and full 65535 range scanning (`-p -`).
- Port Profiles: Supports predefined authorized recon workflows with `--port-profile` for `quick/kokiri`, `web/sheikah`, `mail/rito`, `admin/castle`, and `bugbounty/triforce`.
- Smart Reconnaissance: Features protocol-aware banner probes for HTTP, HTTPS, SMTP, and FTP, SMTP STARTTLS upgrade metadata collection, passive banner fallback for unknown services, TLS certificate metadata extraction for HTTPS/implicit-TLS services, and clickable web service hints for standard and common alternate web ports.
- Clean UI & Reporting: Uses target orientation with effective stance/pacing details, a phase-oriented TCP live display, an Nmap-inspired final panel, quiet automation mode, organized target-specific output workspaces, and clean TXT/JSON report exports.
- Reliability Foundation: Includes standard-library unit tests for CLI parsing, port helpers, banner probing, TLS analysis, JSON export, output helpers, quiet mode, and localhost mock services.

### Passive Subdomain Discovery

- **Multi-Provider Discovery:** Supports Subfinder, Amass, or both providers in the same passive run.
- **Provider Path Control:** Uses provider binaries from `PATH` by default and supports explicit executable paths when needed.
- **Clean Data Handling:** Automatically sanitizes ANSI escape codes, normalizes results to lowercase, deduplicates, and sorts subdomains alphabetically.
- **Provider-Aware Output:** Keeps TXT output simple while JSON export tracks provider counts, merged results, and subdomain source attribution.
- **Activity Telemetry:** Keeps a live enumeration spinner while mapping provider lifecycle events, observed provider output, and timeouts into concise Hylian-themed activity updates.
- **Silent Operations:** Prints a clean final summary to the terminal instead of flooding the screen, keeping TXT and optional JSON outputs clean.

## Requirements

- Python 3 (Standard-library only).
- Linux terminal environment (preferably Kali Linux). Windows supports basic CLI scans/tests through safe terminal fallbacks.
- Subfinder and/or Amass installed and available in your `PATH` for passive discovery, or explicit executable paths passed with `--subfinder-path` / `--amass-path`.

## Testing / CI

HylianScan uses Python standard-library `unittest` for its test suite.

GitHub Actions runs the test workflow on push and pull request events. Localhost mock services validate scanner behavior safely without contacting external targets.

Standard local validation:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall -q hylianscan.py core modules tests
python hylianscan.py --help
```

## Project Layout

```text
hylianscan/
|-- .github/
|   |-- workflows/
|   |   |-- tests.yml
|-- assets/
|   |-- ascii/
|   |   |-- .gitkeep
|-- core/
|   |-- __init__.py
|   |-- banner.py
|   |-- cli.py
|   |-- colors.py
|   |-- output.py
|   |-- panel.py
|   |-- passive_telemetry.py
|   |-- tcp_live_display.py
|   |-- terminal.py
|-- docs/
|   |-- TODO.md
|-- modules/
|   |-- __init__.py
|   |-- banner_grabber.py
|   |-- json_exporter.py
|   |-- ports.py
|   |-- port_profiles.py
|   |-- rate_limiter.py
|   |-- scan_stance.py
|   |-- subdomain.py
|   |-- target.py
|   |-- tcp_scanner.py
|   |-- tls_analysis.py
|-- output/
|   |-- .gitkeep
|-- tests/
|   |-- __init__.py
|   |-- test_banner_grabber.py
|   |-- test_cli.py
|   |-- test_json_exporter.py
|   |-- test_mock_services.py
|   |-- test_output.py
|   |-- test_ports.py
|   |-- test_port_profiles.py
|   |-- test_quiet_mode.py
|   |-- test_rate_limiter.py
|   |-- test_scan_orientation.py
|   |-- test_subdomain.py
|   |-- test_tcp_scanner.py
|   |-- test_tls_analysis.py
|   |-- test_tls_mock_services.py
|-- versions/
|   |-- v0.4_summary.md
|   |-- v0.5_summary.md
|   |-- v0.6_summary.md
|   |-- v0.7_summary.md
|   |-- v0.8_summary.md
|   |-- v0.9_summary.md
|-- .gitattributes
|-- .gitignore
|-- hylianscan.py
|-- README.md
|-- requirements.txt
```

## CLI Arguments

```text
Target IP address or domain name.
-p, --ports            Ports to scan. Supports comma lists, ranges, and "-".
--top-ports            Scan the top N built-in TCP ports.
--port-profile         Use a predefined TCP port profile.
-s, --subfinder        Enable passive subdomain discovery using Subfinder.
--subfinder-path       Path to the Subfinder executable when it is not available in PATH.
-a, --amass            Enable passive subdomain discovery using Amass.
--amass-path           Path to the Amass executable when it is not available in PATH.
--stance               TCP scan stance: fast/din, balanced/nayru, or stealthier/farore.
-t, --threads          Override the selected stance worker count.
-T, --timeout          Override the selected stance timeout per TCP port.
--max-rate             Limit new TCP connection attempts started per second.
-o, --output           Save TCP reports or choose a passive output directory.
--json-output          Save TCP or passive subdomain results as JSON inside the output directory.
--quiet                Reduce terminal output for scripting and automation.
```

## Usage

### TCP Scanning Examples

Scan with default top-ports:

```bash
python3 hylianscan.py scanme.nmap.org
```

Scan custom ports with custom timeout and threads:

```bash
python3 hylianscan.py scanme.nmap.org -p 80,443,8080 -T 1.5 -t 20
```

Scan with the fast stance:

```bash
python3 hylianscan.py scanme.nmap.org --stance fast
```

Use the equivalent Triforce lore alias:

```bash
python3 hylianscan.py scanme.nmap.org --stance din
```

Scan custom port range:

```bash
python3 hylianscan.py 192.168.0.10 -p 1-1000 -T 1.0 -t 50
```

Scan full TCP range (1-65535):

```bash
python3 hylianscan.py 192.168.0.10 -p - -T 1.0 -t 100
```

Scan with high concurrency but paced connection starts:

```bash
python3 hylianscan.py scanme.nmap.org -p 1-1000 -t 300 --max-rate 100
```

Scan a predefined web recon profile:

```bash
python3 hylianscan.py scanme.nmap.org --port-profile web
```

Use the equivalent Zelda alias with stance and pacing controls:

```bash
python3 hylianscan.py scanme.nmap.org --port-profile sheikah --stance fast --max-rate 100
```

Save a TCP scan report:

```bash
python3 hylianscan.py example.com -p 80,443 -o web_report.txt
```

Save a TCP scan report into a target-specific timestamped workspace:

```bash
python3 hylianscan.py example.com -p 80,443 -o
```

Save TCP scan results as JSON:

```bash
python3 hylianscan.py example.com -p 80,443 --json-output tcp_results.json
```

The JSON export includes future-ready TCP findings with raw banner evidence, structured probe metadata, HTTP status/header metadata, Set-Cookie metadata and cookie observations, HTTP security-header observations, HTTP URL, timing, TLS certificate metadata, and TLS risk indicators when a TLS service is detected.

Run an automation-friendly quiet TCP scan:

```bash
python3 hylianscan.py example.com -p 80,443 --quiet
```

### Subdomain Discovery Examples

Run passive discovery with Subfinder only:

```bash
python3 hylianscan.py example.com -s
```

Run passive discovery with Amass only:

```bash
python3 hylianscan.py example.com -a
```

Run passive discovery with both providers:

```bash
python3 hylianscan.py example.com -s -a
```

Run passive discovery with explicit provider paths:

```bash
python3 hylianscan.py example.com -s -a --subfinder-path /opt/tools/subfinder --amass-path /opt/tools/amass
```

Run discovery with a custom output directory:

```bash
python3 hylianscan.py example.com -s -o reports
```

Save passive discovery as TXT and JSON:

```bash
python3 hylianscan.py example.com -s -a --json-output subdomains.json
```

## Execution Notes

Mode Separation: TCP scanning (-p) and passive discovery (-s/-a) are separate modes and cannot be combined in a single command.

Output Behavior: TCP mode shows target orientation, effective scan configuration, scan progress, discovered open ports, service probing status, and a final report. Passive discovery mode shows selected providers and concise activity telemetry, then saves deduplicated results straight to disk. Default TXT/JSON output requests create `output/<target>/<timestamp>/` workspaces with names such as `tcp_report.txt`, `tcp_results.json`, `subdomains.txt`, and `subdomains.json`; explicit user-provided paths keep the existing behavior.


Roadmap: Future work, including wildcard DNS filtering workflows, is tracked in docs/TODO.md.

## Be Safe!

Use this project only in your own lab, authorized networks, or explicit pentest scopes.
