# Hylianscan reporting review

Reviewed on 2026-09-28 using source code, existing tests, official documentation,
mocks, and local test services. No public targets were scanned. Examples below
describe presentation semantics, not measurements of public infrastructure.

## Flow and implementation boundaries

`hylianscan.main()` selects TCP, passive, or XML-import mode. Information commands
exit before scan setup. Normal TCP/passive runs print the startup banner once;
quiet mode suppresses it and live callbacks.

- TCP: target resolution -> optional host discovery -> `scan_tcp_ports()` native
  discovery -> service probes -> HTTP report filter -> optional Nmap enrichment
  using unfiltered native findings -> `core/panel.py` -> terminal, optional TXT,
  optional JSON. Findings retain address, family, and IPv6 scope ID. Host discovery
  exclusions are appended to terminal/TXT and exported to JSON.
- Passive: sequential Subfinder/Amass runs -> optional DNSx validation -> sorted,
  deduplicated names -> mandatory `subdomains.txt` -> optional HTTPx and its JSONL
  -> optional passive JSON -> summary. Provider failure saves partial results
  before raising the existing error. It does not pass through the success summary.
- XML import: parse a supplied XML file -> require one up host -> show imported
  open TCP evidence -> optional TXT/JSON. It performs no native scan.
- `core/output.py` owns path resolution, ANSI removal, and report persistence.
  Native JSON schema v2, passive JSON v1, Nmap import JSON, and HTTPx JSONL remain
  unchanged. No scan options, pacing, timeouts, provider flags, parser assumptions,
  or enrichment selection rules were changed.

## Reference tools

| Tool / official reference | Lesson applied | Why behavior is not directly comparable |
| --- | --- | --- |
| [Nmap normal output](https://nmap.org/book/output-formats-normal-output.html) | Keep scan context and discovered states explicit; saved reports omit progress noise. | Nmap supports multiple scan techniques and service/version detection. Hylianscan native service names remain port hints in JSON. |
| [Nmap port states](https://nmap.org/book/man-port-scanning-basics.html) | Keep observations distinct from inferred states. | Nmap's state vocabulary reflects its scan methods and packet evidence. A Hylianscan connect timeout alone cannot establish filtering or closure. |
| [Naabu examples](https://docs.projectdiscovery.io/opensource/naabu/running) | Keep IP/port attribution explicit; distinguish discovery from later HTTP evidence; preserve structured output. | The examples show compact endpoint streams and JSONL, plus optional follow-up tools. Hylianscan has its own probes and one structured run document. Naabu's packet-rate setting is not Hylianscan's connection-start pacer. |
| [RustScan README](https://github.com/bee-san/RustScan/blob/master/README.md) | Clearly separate port discovery from enrichment. | RustScan advertises automatic handoff to Nmap and scripting. Hylianscan probes natively; Nmap remains explicitly optional. Performance claims are not a basis for adopting its timing defaults. |
| [Subfinder examples](https://docs.projectdiscovery.io/opensource/subfinder/running) | Names, result count, and a reusable output list are the passive workflow's primary products. | Hylianscan orchestrates multiple providers and can separately run DNSx/HTTPx. A discovered name is not evidence of a responding service. |
| [Amass user guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md) | Keep provenance and distinguish passive collection from validation. | The guide distinguishes passive, normal DNS validation, and active modes and describes a graph database. Hylianscan's saved TXT is a name list, not that database. The guide is version-dependent; no Amass flags or parser behavior were changed based on it. |

## Field placement

The following inventory covers existing display fields and the structured fields
that support them. “JSON” means retained when that export is requested; it does
not mean evidence was removed from the in-memory result.

| Field | Human-readable placement | Assessment / structured evidence |
| --- | --- | --- |
| Startup logo, tool version, author | One startup banner; compact text on narrow terminals | Keep identity; avoid repeating full art in final output. |
| Triforce / Sheikah theme | One bracketed final mark above the compact TCP report; quiet output omits it | Keep identity without repeating decorative separators. |
| Target hostname | Report heading | Identifies user intent; does not prove reachability. |
| Target addresses and IPv6 scope | Summary and each `Open IP:port` finding | Scope IDs must distinguish link-local interfaces. Never assign an addressless finding to an arbitrary IP. |
| Reverse DNS / address family | JSON | IP text is sufficient in the main report; PTR is metadata, not service identity. |
| Scan mode, selected-port count, profile/scope label | Summary | Count is per address; completed attempts count address/port combinations. |
| Exact requested port list | JSON | Avoid a 65,535-number TXT dump; no change to requested-port evidence. |
| Workers, socket/probe/resolve timeouts, stance, rate, optional stages | Startup orientation where already present; complete effective settings in JSON | Duplicated configuration dictionaries removed from final TXT. No flags changed. |
| Run completion / interruption | Summary, alongside completed and planned attempts | Existing `partial` conflates state uncertainty and execution completeness. Rendering uses counts, preserves interruption, and leaves JSON status unchanged. |
| Duration | Summary | Full elapsed time when orchestration provides it; native discovery/probing duration for direct renderer callers. Individual phases remain JSON. |
| Open endpoints | Results summary and rows | Native count before HTTP filtering. The same port on two IPs is two endpoints. |
| Refused connections | Results summary when nonzero | Report observed refusal; no unnecessary claim about why it happened. |
| Timeout, unreachable, other connection errors | Results summary when nonzero | Explicitly unknown port state. No timeout-to-closed or timeout-to-filtered conversion. |
| Attempts lacking a recorded outcome | Missing outcomes line when nonzero | An interrupted/unfinished execution is distinct from finished attempts with unknown states. |
| OS connection error codes | JSON | Preserve exact diagnostic counts without dumping Python dictionaries into human output. |
| Host discovery method, attempted ports, excluded addresses, outcome/error | Existing separate terminal/TXT block and JSON | Unconfirmed is not down. These observations belong to discovery, not port-scan outcomes. |
| Host reachability wording | Open endpoint lines identify concrete evidence | A multi-address heading does not mean every address responded; addresses without findings remain separately qualified. |
| Addresses without displayed findings | Per-address note for multi-address reports | State that no open TCP port was observed, or that no finding matched the active HTTP filter. Omit the note when an open finding has no recorded address. |
| Port / transport / open state | `Open IP:port` line | State remains open if later probing fails. |
| Port-derived service name | JSON | A port-derived name is not confirmation. |
| HTTP status and Location | JSON | Only parsed HTTP responses produce this signal. |
| HTTP Server and Content-Type | JSON | Useful self-reported evidence; not validated product identity. |
| Other HTTP headers, framing completeness, security-header analysis | JSON | A missing-header observation does not by itself establish a vulnerability. Existing completeness guards stay intact. |
| Guessed web URL | JSON | Port-based URL construction does not establish that HTTP responded. |
| Non-HTTP banner | JSON | Full banner remains available without a multiline protocol transcript in the terminal. |
| Probe status | JSON | Open port, completed probe, identified service, and HTTP response are separate concepts. |
| Probe name, method, transport, raw error, captured bytes | JSON | Exact method/error/base64 bytes retained; generic failure status stays visible without leaking TLS diagnostics into TXT. |
| TLS handshake protocol/cipher, certificate, SANs, issuer, validity, trust, analysis/reasons, upgrade metadata | JSON only | Removed TLS version fallback, risk lines, certificate summary, and TXT explanations. Collection and analysis are unchanged. Protocol banner text can still mention STARTTLS as received application evidence. |
| Per-connection response timing | JSON | It is not a blanket host latency measurement. |
| HTTP report filter and shown/hidden counts | Summary whenever selected | Label explicitly as report-only. Does not describe reduced scan traffic. |
| Run ID, start/finish timestamps | TXT footer and JSON | Keep report correlation without repeating execution status/outcome dictionaries. |
| Passive domain | Heading | Replaces ambiguous “Target Realm” label. |
| Passive candidate count | Summary | Sum of provider name-list lengths before cross-provider deduplication; not a count of raw provider stdout records. |
| Unique passive names saved | Summary | Describes final list, which can be DNSx-filtered. Does not imply live hosts. |
| Provider name, status, returned-name count | Provider table | Success with zero names is different from timeout/failure. Provider status is available in `ProviderRunResult`. |
| Passive provider exit code, reason, source attribution, candidate list, DNSx metadata | JSON; failure reason also in terminal error | Final TXT remains a sorted name list usable in pipelines. Detailed provenance is not inserted into that file. |
| DNS validation status | Passive summary | Separates passive candidates, DNSx A/AAAA evidence, and untested service reachability. |
| Passive TXT path | Summary, labeled Output Path | “Slate Database” overstated what the plain name-list file contains. |
| HTTPx status, requested targets, returned records, reason/path | Optional enrichment summary | “Targets probed” was false on skipped execution; record count alone does not prove each record is a live service. JSON compatibility fields are retained. |
| HTTPx status code, URL, title, technologies | Optional table, existing 20-record preview | Complete records remain JSONL and optional passive JSON. Wrap and escape controls in display. |
| Nmap service scan target, requested ports, status/reason, elapsed time | One optional summary with per-address rows | “Ports scanned” was false for skipped/failed execution. One header covers every address, including partial evidence. |
| Nmap port/state/service/version | Indented lines below the optional Nmap stage; method remains structured evidence | Native and Nmap observations remain separate; method/confidence stay in JSON. |
| Nmap state disagreements, missing per-port evidence, warnings | Optional details | Native evidence is retained; a later observation is not a retroactive rewrite. |
| Nmap source XML/path, run completion, imported host/open count | XML import summary | Identifies imported evidence; no claim of a fresh live scan. |
| Nmap confidence, product/version/extrainfo, CPE, execution argv/stdout/stderr | Import method/confidence detail where already present; full structured evidence in JSON | Import has explicit PORT/STATE/SERVICE/VERSION headings. No parser/integration changes. |
| Decorative separators / duplicate run fields | No final TCP frame; quiet output remains plain | Run and outcome summaries remain compact and separate. |

## Semantic checks and limitations

The motivating example is covered with synthetic addresses and two findings on
only one IP: 131,070 finished attempts, two open endpoints, 131,068 timeouts. The
human report says the run finished and states that timed-out port states are
unknown. The second IP has no displayed findings; it is not labeled up or down.

Confirmed constraints left outside this presentation refactor:

- Native non-open outcomes are aggregate counters. Per-IP refusal/timeout counts
  and a list of definitively nonresponding IPs cannot be reconstructed. Adding them
  would require scanner/model/export changes.
- JSON v2 `scan.status` can remain `partial` after every attempt finishes, and
  `scope.ports_tested` is the selected per-address count even after interruption.
  Consumers must also inspect requested ports, completed attempts, and outcomes.
  Renaming or redefining those compatibility fields was not necessary here.
- HTTPx stores requested targets and arbitrary JSON objects, not verified attempt
  completion. Its existing JSON `live_services` compatibility key counts records;
  this refactor corrects the human label without changing that key or its meaning.
- HTTPx timeout/failure discards partial subprocess output in its current runner;
  provider setup failures and passive interruption can bypass the final summary.
  Changing retention/cancellation paths is separate execution work.
- `clean_subdomain()` cleans names without enforcing domain membership. This
  refactor does not expand or validate the optional active HTTPx scope.
- The old agent guide said provider results were bare lists. Current implementation
  and tests already use `ProviderRunResult`; the guide was corrected.

Terminal widths are handled using the standard library, with regression checks
at 40 columns and a compact startup banner at 32. Character counts are not a full
terminal-cell calculation for wide CJK or combining glyphs. Live progress/spinner
rendering on real Windows/Kali terminals and font-specific Triforce appearance
still warrant manual inspection. Animated README images are historical captures.

No additional report format or verbosity flag was introduced. Full evidence is
available through the existing explicit JSON option; human-readable layouts are
not intended as a stable machine-parsing contract.

## Modified files

| Files | Change |
| --- | --- |
| `core/panel.py` | Shared compact TCP endpoint layout, address association, outcome counts, compact TXT. |
| `core/terminal.py`, `core/banner.py` | Plain report wrapping and narrow startup fallback. |
| `core/passive_display.py`, `core/tcp_live_display.py` | Provider status table, precise candidate/endpoint wording, scoped IPv6 live labels. |
| `hylianscan.py` | Pass provider status to rendering and place Nmap text before the TXT metadata footer. |
| `core/cli.py` | Explain existing JSON option's TLS evidence in help. |
| `modules/nmap_enrichment.py`, `modules/nmap_xml.py` | Compact Nmap follow-up lines, requested-scope wording, service source, import table headings, wrapping. |
| `modules/httpx_runner.py` | Requested-target/record labels, display control escaping and wrapping. |
| `tests/test_panel.py`, `tests/test_quiet_mode.py`, `tests/test_passive_output.py`, `tests/test_subdomain.py` | Updated layouts and semantic regression checks. |
| `tests/test_nmap_enrichment.py`, `tests/test_nmap_xml.py`, `tests/test_scan_integrity.py`, `tests/test_httpx_runner.py` | Optional-report checks, partial Nmap status/header retention, HTTPx display safety. |
| `README.md`, `AGENTS.md`, `docs/reporting_review.md` | Examples, current contracts, comparisons, field inventory, and limitations. |
