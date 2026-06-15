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

## v0.6 Completed

- [x] Centered and visually aligned the HylianScan banner in the terminal interface.
- [x] Defined official terminal color variables (`ALERT_RED`, `HACKER_GREEN`, etc).
- [x] Implemented core screen control functions (`clear_screen`, `clear_dynamic_line`).
- [x] Created the real-time dynamic line overwriting system (`write_dynamic_line`).
- [x] Structured the final visual panel layout for open ports display.

## v0.7 Completed

- [x] Upgraded Subfinder execution from blocking `subprocess.run()` to streaming `subprocess.Popen()`.
- [x] Streamed Subfinder `stderr` telemetry into the dynamic terminal line renderer.
- [x] Prevented passive discovery from flooding the terminal with thousands of subdomains.
- [x] Enforced mandatory text-file saving for passive subdomain results.
- [x] Added default passive output file: `output/hylianscan_subdomains.txt`.
- [x] Added directory-based passive output handling: `-o <directory>` writes `subdomains.txt`.
- [x] Replaced subdomain-flow yellow/orange status messages with `ALERT_RED`.
- [x] Added a clean `HACKER_GREEN` passive discovery completion summary.
- [x] Fully removed legacy multithreaded/socket brute-force dead code from `modules/subdomain.py`.

## v0.8 Completed

- [X] Move `TOP_400_TCP_PORTS` from `hylianscan.py` into a dedicated `modules/ports.py` file.
- [X] Extract TCP banner grabbing into `modules/banner_grabber.py`.
- [X] Separate raw TCP scan data from ANSI-rendered output where appropriate.
- [X] Add JSON export into `output/`.
- [X] Add TLS certificate metadata extraction to TCP JSON export.
- [X] Add compact HTTP terminal summaries for protocol-aware banners.
- [X] Replace `--subdomains` with `--subfinder` while preserving `-s`.
- [X] Add Amass as a second passive subdomain discovery provider.
- [X] Add multi-provider passive discovery with deduplicated TXT output.
- [X] Add provider source attribution to passive subdomain JSON export.
- [X] Add configurable worker profiles for fast, balanced, and stealthier scan modes.
- [X] Add protocol-aware banner probes for HTTP, SMTP, FTP, and TLS.
- [X] Add unit tests for CLI parsing, port normalization, banner cleanup, JSON export, TLS analysis, output helpers, quiet mode, and localhost mock services.
- [X] Add a quiet mode for automation-friendly output.
- [X] Add JSON export for passive subdomain discovery.

## v0.9 Completed

- [X] Add structured HTTP metadata extraction to JSON reports.
- [X] Add passive provider activity telemetry with timeout-safe partial results.
- [X] Add Windows-safe terminal fallbacks for non-POSIX environments.
- [X] Add passive lifecycle telemetry beneath the enumeration spinner.
- [X] Polish passive discovery terminal styling with character-name highlighting.
- [X] Merge TCP scan stance details into the Target Orientation block.
- [X] Refactor the startup banner to Slant TrueColor RGB rendering.
- [X] Add TLS certificate expiry and hostname-mismatch risk indicators.
- [X] Add alternate HTTP/HTTPS web port service and probe mappings.
- [X] Polish live TCP output and custom scan-scope wording.
- [X] Refine TCP final output with Nmap-inspired `PORT / STATE / SERVICE / VERSION` formatting.
- [X] Add phase-oriented TCP live output for connect-scan discovery and service probing.
- [X] Add protocol probe registry to make service fingerprinting easier to extend.
- [X] Add SMTP STARTTLS upgrade probing for TLS metadata collection.
- [X] Add local mock-service tests for safe localhost TCP and HTTP probing.
- [X] Add output helper tests for TXT, JSON, and passive discovery file handling.
- [X] Add quiet-mode tests to verify automation-friendly plain output.

## v0.10 / v1.0 Future Work

- [ ] Add TXT report export templates into `output/`.
- [ ] Add IPv6 support with `socket.getaddrinfo()`.
- [ ] Add structured scan profiles.
- [ ] Add configurable Subfinder binary path support.
- [ ] Add configurable Amass binary path support.
- [ ] Add STARTTLS upgrade probes for IMAP, POP3, LDAP, and FTP.
- [X] Add local TLS mock-service tests for HTTPS certificate and TLS metadata parsing.
- [X] Add local SMTP and FTP mock-service tests for protocol-aware banner parsing.
- [ ] Add scan intensity profiles with rate limiting and jitter controls.
- [ ] Add CI coverage reporting.

## Long-Term Research

- [ ] UDP scanning fundamentals.
- [ ] Service fingerprinting.
- [ ] Rate limiting and scan safety.
- [ ] Stealth scan theory.
- [ ] DNS wildcard detection for subdomain enumeration.
- [ ] Report templates for authorized pentest labs.
