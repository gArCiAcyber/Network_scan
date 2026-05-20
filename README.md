# hylianscan

`hylianscan` is an educational Python 3 networking and offensive-security lab tool for authorized environments, built for Kali Linux.

## v0.4 Focus

- Clean professional architecture.
- High-performance threaded TCP scanning.
- Safe terminal UX.
- Real-time progress feedback.
- Final consolidated scan panel.

## Structure

```text
hylianscan/
├── core/
│   ├── __init__.py
│   ├── banner.py
│   ├── colors.py
│   ├── panel.py
│   └── terminal.py
├── docs/
│   └── README_STUDIES.md
├── modules/
│   ├── __init__.py
│   ├── target.py
│   └── tcp_scanner.py
├── output/
├── TODO.md
├── hylianscan.py
└── requirements.txt
```

## Usage

```bash
python3 hylianscan.py
```

Use this project only in your own lab, authorized networks, or explicit pentest scopes.

