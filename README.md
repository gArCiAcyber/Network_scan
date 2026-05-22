# hylianscan

`hylianscan` is an educational Python3 networking and offensive security lab tool designed for authorized environments, bringing you a Zelda-themed scanning experience built for Kali Linux.
## v0.4 Focus

- Clean architecture.
- High-performance threaded TCP scanning.
- Safe terminal UX.
- Real-time progress feedback.
- Final consolidated scan panel.

## Structure

```text
hylianscan/
├── assets/ascii
│   ├──.gitkeep
├── core/
│   ├── __init__.py
│   ├── banner.py
│   ├── colors.py
│   ├── panel.py
│   └── terminal.py
├── docs/
│   └── TODO.md
├── modules/
│   ├── __init__.py
│   ├── target.py
│   └── tcp_scanner.py
├── output/
| └── .gitkeep
├── versions/
| └── v0.4_summary.md
├── gitignore. 
├── hylianscan.py
├── README.md
├── requirements.txt

```

## Usage

```bash
python3 hylianscan.py
```

Use this project only in your own lab, authorized networks, or explicit pentest scopes.

