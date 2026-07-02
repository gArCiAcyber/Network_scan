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
- [X] Add structured probe metadata to TCP JSON reports.
- [X] Add structured HTTP Set-Cookie analysis to TCP JSON reports.
- [X] Add structured HTTP security-header observations to TCP JSON reports.
- [X] Add TCP max-rate pacing for controlled connection start rates.
- [X] Show effective TCP stance, pacing, and override configuration during scan orientation.
- [X] Add predefined TCP port profiles with technical names and Zelda aliases.
- [X] Add explicit Subfinder and Amass executable path handling for passive discovery.
- [X] Add local mock-service tests for safe localhost TCP and HTTP probing.
- [X] Add output helper tests for TXT, JSON, and passive discovery file handling.
- [X] Add quiet-mode tests to verify automation-friendly plain output.

## v1.0 Preparation Completed

- [X] Add target-specific timestamped output workspaces for default TXT and JSON exports.
- [X] Add source-based `pip install` support through `pyproject.toml`.
- [X] Add `pipx` installation documentation as the recommended CLI install path.
- [X] Add GitHub Actions validation for `pipx install`.
- [X] Add local `scripts/validate_pipx_install.sh` automation.
- [X] Add cross-platform `scripts/validate_release.py` release validation automation.
- [X] Add packaging metadata tests for `pyproject.toml`.
- [X] Add CLI `--version` support backed by centralized version metadata.
- [X] Add explicit `-u / --url` target flag while preserving positional targets.
- [X] Add IMAP STARTTLS upgrade probing.
- [X] Add POP3 STLS upgrade probing.
- [X] Add FTP AUTH TLS upgrade probing.
- [X] Add structured TLS risk explanations to saved reports.
- [X] Add predefined TCP port profiles with technical names and Zelda aliases.
- [X] Add information-only CLI commands for listing built-in port profiles and scan stances.
- [X] Add TCP max-rate pacing for controlled connection start rates.
- [X] Add structured probe metadata to TCP JSON reports.
- [X] Add structured HTTP security-header observations.
- [X] Add structured HTTP Set-Cookie observations.
- [X] Add explicit Subfinder and Amass executable path handling.
- [X] Show effective scan stance, pacing, and user overrides during scan orientation.
- [X] Polish README installation and showcase structure for v1.0 development.
- [X] Add safer localhost-focused tests and packaging validation coverage.
- [X] Add README example validation tests for documented CLI commands and assets.
- [X] Add a public v1.0 release checklist under `docs/`.
- [X] Add Nmap XML import foundation with `--nmap-xml`.

## v1.0 Must-Have Before Release

- [ ] Run `scripts/validate_release.py` from a clean checkout.
- [ ] Verify GitHub Actions `tests` and `pipx install` workflows pass on the final main branch.
- [ ] Confirm `pipx install git+https://github.com/gArCiAcyber/Network_scan.git` works after the final release push.
- [ ] Complete the final v1.0 release checklist.
- [ ] Confirm documented TCP, passive discovery, match-code, and output workspace examples still work.
- [ ] Perform one final README consistency audit against `python hylianscan.py --help`.
- [ ] Tag the release only after validation and documentation checks pass.

## Post-v1.0 Future Work

- [ ] Add optional live Nmap enrichment runner after native TCP scanning.
- [ ] Add TXT report export templates into `output/`.
- [ ] Add IPv6 support with `socket.getaddrinfo()`.
- [ ] Add structured scan profiles.
- [ ] Add LDAP STARTTLS upgrade probing.
- [ ] Add scan intensity profiles with rate limiting and jitter controls.
- [ ] Add CI coverage reporting.
- [ ] Extract reusable test fixtures for certificates, mock services, HTTP samples, and scan result builders.
- [ ] Evaluate optional PyPI publication after the source and `pipx` install paths are stable.

## Long-Term Research

- [ ] UDP scanning fundamentals.
- [ ] Service fingerprinting.
- [ ] Rate limiting and scan safety.
- [ ] Stealth scan theory.
- [ ] DNS wildcard detection for subdomain enumeration.
- [ ] Report templates for authorized pentest labs.
