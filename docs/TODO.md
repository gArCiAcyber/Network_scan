# hylianscan Roadmap

## v0.4 Completed

- [x] Split `core/` into dedicated banner, color, terminal, and panel modules.
- [x] Added `modules/target.py` for input validation and IPv4 DNS resolution.
- [x] Refactored `modules/tcp_scanner.py` into a multithreaded TCP scanning engine.
- [x] Added `ThreadPoolExecutor` for high-performance I/O-bound scanning.
- [x] Added thread-safe terminal progress rendering.
- [x] Added instant open-port reporting through callbacks.
- [x] Added safe terminal pause handling for arrow-key and mouse-scroll artifacts.
- [x] Added graceful `KeyboardInterrupt` handling.
- [x] Added final static consolidation panel.
- [x] Standardized the terminal footer as `[ HYLIANSCAN v0.4 - BY CYLINK ]`.
- [x] Simplified the banner by keeping only the Link ASCII art and standardized footer.
- [x] Renamed the final panel title to `SCAN POWERED BY THE TRIFORCE`.
- [x] Removed the `-v` / `--verbose` CLI mode to keep terminal output deterministic.

## v0.5 Completed

- [x] Added `modules/subdomain.py` as a dedicated subdomain enumeration engine.
- [x] Implemented subdomain brute-force with native `socket`, `threading`, and `queue`.
- [x] Added `-w / --wordlist` to activate subdomain enumeration mode.
- [x] Changed timeout flag from `-t / --timeout` to `-T / --timeout`.
- [x] Added `-t / --threads` for configurable concurrency across supported scan modes.
- [x] Preserved TCP port scanning mode with `-p / --ports` and `--top-ports`.
- [x] Added `-p -` shortcut for full TCP range scanning from `1` to `65535`.
- [x] Added mode validation to prevent mixing subdomain enumeration with TCP port flags.
- [x] Added a static subdomain results panel and output-file support for enumeration results.

## v0.6 Ideas

- [ ] Move `TOP_400_TCP_PORTS` from `hylianscan.py` into a dedicated `modules/ports.py` file.
- [ ] Add JSON export into `output/`.
- [ ] Add TXT report export templates into `output/`.
- [ ] Add configurable worker profiles for fast, balanced, and stealthier scan modes.
- [ ] Add protocol-aware banner probes for HTTP, SMTP, FTP, and TLS.
- [ ] Add IPv6 support with `socket.getaddrinfo()`.
- [ ] Add unit tests for target parsing, port normalization, banner cleanup, and subdomain enumeration.
- [ ] Add a quiet mode for automation-friendly output.
- [ ] Add structured scan profiles.

## Long-Term Research

- [ ] UDP scanning fundamentals.
- [ ] Service fingerprinting.
- [ ] Rate limiting and scan safety.
- [ ] Stealth scan theory.
- [ ] DNS wildcard detection for subdomain enumeration.
- [ ] Report templates for authorized pentest labs.
