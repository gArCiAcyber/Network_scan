# hylianscan

`hylianscan` is a Python 3 reconnaissance and networking lab tool built for authorized targets, Kali Linux workflows, and practical study of offensive security automation.

The current development version is `v0.7-dev`.

## Scope

Use this project only in your own lab, authorized networks, or explicit pentest scopes.

## Current Capabilities

### TCP Port Scanning
````
- Flexible Targeting: Resolves domains to IPv4 addresses or accepts direct IPs.
- High Performance: Multi-threaded TCP scanning utilizing ThreadPoolExecutor` and socket.connect_ex().
- Custom Port Selection: Supports comma-separated lists (-p 80,443), explicit ranges (-p 1-1000), top-port presets (--top-ports), and full 65535 range scanning (-p -).
- Smart Reconnaissance: Features lightweight passive banner grabbing through a dedicated banner module and generates clickable web service hints for standard HTTP/HTTPS ports.
- Clean UI & Reporting: Renders a final security-focused terminal panel and supports saving clean TCP reports with -o / --output.
````
### Passive Subdomain Discovery
- **Subfinder Integration:** Leverages Subfinder via subprocesses with dynamic stderr telemetry streaming.
- **Clean Data Handling:** Automatically sanitizes ANSI escape codes, normalizes results to lowercase, deduplicates, and sorts subdomains alphabetically.
- **Silent Operations:** Prints a clean final summary to the terminal instead of flooding the screen, keeping outputs clean.

## Requirements

- Python 3 (Standard-library only).
- Linux terminal environment (preferably Kali Linux).
- Subfinder installed and available in your `PATH`.

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
|-- .gitattributes
|-- .gitignore
|-- hylianscan.py
|-- README.md
|-- requirements.txt
```
# CLI Arguments
``Target IP address or domain name.``
-p, --ports            Ports to scan. Supports comma lists, ranges, and "-".
--top-ports            Scan the top N built-in TCP ports.
-s, --subdomains       Enable passive subdomain discovery using Subfinder.
-t, --threads          Number of concurrent TCP scanner workers.
-T, --timeout          TCP connection timeout per port in seconds.
-o, --output           Save TCP reports or choose a Subfinder output directory.
## Usage
``TCP Scanning Examples``

 Scan with default top-ports
````python3 hylianscan.py scanme.nmap.org
```
 Scan custom ports with custom timeout and threads
python3 hylianscan.py scanme.nmap.org -p 80,443,8080 -T 1.5 -t 20

 Scan custom port range
python3 hylianscan.py 192.168.0.10 -p 1-1000 -T 1.0 -t 50

 Scan full TCP range (1-65535)
python3 hylianscan.py 192.168.0.10 -p - -T 1.0 -t 100

 Save a TCP scan report
python3 hylianscan.py example.com -p 80,443 -o web_report.txt
Subdomain Discovery Examples

 Run passive subdomain discovery (saves to output/hylianscan_subdomains.txt)
python3 hylianscan.py example.com -s
````
## Run discovery with a custom output directory
````bashpython3 hylianscan.py example.com -s -o reports
Execution Notes
Mode Separation: TCP scanning (-p) and subdomain discovery (-s) are separate modes and cannot be combined in a single command.

Output Behavior: TCP mode prints live findings on screen. Subdomain mode runs silently in the background, showing execution telemetry, and saves the final result straight to disk.

Educational Notes: The estudos/ directory contains detailed development notes and research written in Brazilian Portuguese.

Roadmap: Future work, including wildcard DNS filtering workflows, is tracked in docs/TODO.md.
`````
# Be Safe!
Use this project only in your own lab, authorized networks, or explicit pentest scopes.
