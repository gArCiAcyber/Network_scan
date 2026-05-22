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

## v0.5 Ideas

- [ ] Add JSON export into `output/`.
- [ ] Add TXT report export into `output/`.
- [ ] Add custom port ranges from CLI arguments.
- [ ] Add configurable worker count.
- [ ] Add protocol-aware banner probes for HTTP, SMTP, FTP, and TLS.
- [ ] Add IPv6 support with `socket.getaddrinfo()`.
- [ ] Add unit tests for target parsing, port normalization, and banner cleanup.
- [ ] Add a quiet mode for automation-friendly output.
- [ ] Add structured scan profiles.

## Long-Term Research

- [ ] UDP scanning fundamentals.
- [ ] Service fingerprinting.
- [ ] Rate limiting and scan safety.
- [ ] Stealth scan theory.
- [ ] Report templates for authorized pentest labs.
