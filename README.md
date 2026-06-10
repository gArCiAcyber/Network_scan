# hylianscan

`hylianscan` is a Python 3 reconnaissance and networking lab tool built for authorized targets, Kali Linux workflows, and practical study of offensive security automation.

The current release version is `v0.8`.

## Scope

Use this project only in your own lab, authorized networks, or explicit pentest scopes.

## Current Capabilities

### TCP Port Scanning

- Flexible Targeting: Resolves domains to IPv4 addresses or accepts direct IPs.
- High Performance: Multi-threaded TCP scanning utilizing `ThreadPoolExecutor` and `socket.connect_ex()`.
- Custom Port Selection: Supports comma-separated lists (`-p 80,443`), explicit ranges (`-p 1-1000`), top-port presets (`--top-ports`), and full 65535 range scanning (`-p -`).
- Smart Reconnaissance: Features protocol-aware banner probes for HTTP, HTTPS, SMTP, and FTP, passive banner fallback for unknown services, TLS certificate metadata extraction for HTTPS/implicit-TLS services, and clickable web service hints for standard HTTP/HTTPS ports.
- Clean UI & Reporting: Renders a final security-focused terminal panel and supports saving clean TCP reports with `-o / --output`.

### Passive Subdomain Discovery

- **Multi-Provider Discovery:** Supports Subfinder, Amass, or both providers in the same passive run.
- **Clean Data Handling:** Automatically sanitizes ANSI escape codes, normalizes results to lowercase, deduplicates, and sorts subdomains alphabetically.
- **Provider-Aware Output:** Keeps TXT output simple while JSON export tracks provider counts, merged results, and subdomain source attribution.
- **Silent Operations:** Prints a clean final summary to the terminal instead of flooding the screen, keeping TXT and optional JSON outputs clean.

## Requirements

- Python 3 (Standard-library only).
- Linux terminal environment (preferably Kali Linux).
- Subfinder and/or Amass installed and available in your `PATH` for passive discovery.

## Project Layout

```text
hylianscan/
|-- assets/
|   |-- ascii/
|   |   |-- .gitkeep
|-- core/
|   |-- __init__.py
|   |-- banner.py
|   |-- colors.py
|   |-- panel.py
|   |-- terminal.py
|-- docs/
|   |-- TODO.md
|-- modules/
|   |-- __init__.py
|   |-- banner_grabber.py
|   |-- ports.py
|   |-- scan_stance.py
|   |-- subdomain.py
|   |-- target.py
|   |-- tcp_scanner.py
|-- output/
|   |-- .gitkeep
|-- versions/
|   |-- v0.4_summary.md
|   |-- v0.5_summary.md
|   |-- v0.6_summary.md
|   |-- v0.7_summary.md
|   |-- v0.8_summary.md
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
-s, --subfinder        Enable passive subdomain discovery using Subfinder.
-a, --amass            Enable passive subdomain discovery using Amass.
--stance               TCP scan stance: fast/din, balanced/nayru, or stealthier/farore.
-t, --threads          Override the selected stance worker count.
-T, --timeout          Override the selected stance timeout per TCP port.
-o, --output           Save TCP reports or choose a passive output directory.
--json-output          Save TCP or passive subdomain results as JSON inside the output directory.
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

Save a TCP scan report:

```bash
python3 hylianscan.py example.com -p 80,443 -o web_report.txt
```

Save TCP scan results as JSON:

```bash
python3 hylianscan.py example.com -p 80,443 --json-output tcp_results.json
```

The JSON export includes future-ready TCP findings with banner, HTTP URL, timing, and TLS certificate metadata when a TLS service is detected.

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

Output Behavior: TCP mode prints live findings on screen. Passive discovery mode shows selected providers, runs silently in the background, and saves deduplicated results straight to disk.

Educational Notes: The estudos/ directory contains detailed development notes and research written in Brazilian Portuguese.

Roadmap: Future work, including wildcard DNS filtering workflows, is tracked in docs/TODO.md.

## Be Safe!

Use this project only in your own lab, authorized networks, or explicit pentest scopes.
