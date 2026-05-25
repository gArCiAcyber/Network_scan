# hylianscan

`hylianscan` is a Python 3 reconnaissance and networking lab tool inspired by "The Legend of Zelda" trilogy, built for authorized environments and Kali Linux workflows.

## Current Capabilities

- Threaded TCP port scanning.
- Custom port lists and port ranges.
- Top-port scanning presets.
- Full TCP range shortcut with `-p -`.
- Configurable thread count with `-t / --threads`.
- Configurable TCP timeout with `-T / --timeout`.
- Subdomain brute-force enumeration with `-w / --wordlist`.
- Dynamic terminal progress feedback.
- Final consolidated terminal panels.
- Optional report output into `output/`.

## Structure

```text
hylianscan/
|-- core/
|   |-- __init__.py
|   |-- banner.py
|   |-- colors.py
|   |-- panel.py
|   `-- terminal.py
|-- docs/
|   `-- TODO.md
|-- estudos/
|   |-- README.md
|   `-- v0.5_subdomain_enumeration.md
|-- modules/
|   |-- __init__.py
|   |-- subdomain.py
|   |-- target.py
|   `-- tcp_scanner.py
|-- output/
|-- versions/
|   |-- v0.4_summary.md
|   `-- v0.5_summary.md
|-- .gitignore
|-- hylianscan.py
`-- requirements.txt
Usage
TCP scan with custom ports
Bash
python3 hylianscan.py scanme.nmap.org -p 80,443 -T 1.5 -t 20
TCP scan with top ports
Bash
python3 hylianscan.py example.com --top-ports 400 -t 50
Full TCP range scan
Bash
python3 hylianscan.py 192.168.0.10 -p - -T 1.0 -t 100
Subdomain enumeration
Bash
python3 hylianscan.py example.com -w wordlists/subdomains.txt -t 20
Save report
Bash
python3 hylianscan.py example.com -w subs.txt -o subdomains.txt
Safety Rule
Use this project only in your own lab, authorized networks, or explicit pentest scopes.