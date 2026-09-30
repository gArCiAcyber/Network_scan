# Native TCP benchmark on Kali

Run from a source checkout as an ordinary user. The harness uses sudo for
disposable laboratory setup, namespace entry, and cleanup. The scanner and
services have no elevated capabilities. Hylianscan's runtime dependencies,
scan behavior, and exported JSON schema are unchanged.

## Start a battery

Install the benchmark executables inside the Kali VM:

```sh
sudo apt update
sudo apt install python3 hyperfine iproute2 nftables util-linux time
python3 scripts/benchmark.py --benchmark tcp_scan
python3 scripts/benchmark.py --benchmark tcp_scan --profile full
```

`--benchmark tcp_scan` selects the native TCP tests. `--profile quick|full`
selects their workloads and repetition counts, with `quick` as the default.
Both profiles validate every execution against the expected results.
`--benchmark subdomain` selects the separate [offline passive battery](benchmark_subdomain.md),
which requires only Python and works on Windows and Linux. Omitting
`--benchmark` defaults to `tcp_scan`, preserving existing commands.

Run the harness without `sudo`. It asks sudo to authenticate before laboratory
creation. Sudo, namespace entry, privilege changes, readiness, validation, and
cleanup are outside the timed Hylianscan command. The total battery clock
includes them, including time spent authenticating.

The harness checks the installed tools' help/version and Hyperfine's actual
JSON exports. Builds with native peak-memory export use it. Other builds use
GNU `/usr/bin/time` in separately identified companion executions. Installing
GNU Time does not wrap or alter the primary Hyperfine timing.

## Laboratory and expected results

Each execution gets fresh scanner/target namespaces and a veth pair. Their
IPv4 addresses are `192.0.2.1/30` and `192.0.2.2/30`. There is no default route,
bridge, forwarding setup, or public target. Optional `--delay-ms` applies that
many milliseconds in **each direction**; expected added round-trip delay is
twice the configured value.

The services use the dispatcher's existing unprivileged HTTP/HTTPS ports,
8080 and 8443. No privileged-port sysctl or host firewall change is needed.
Generic banners carry their port number so evidence can be matched precisely.
The TLS context reuses the committed test certificate fixture; successful
collection does not imply certificate trust.

| Scenario | Conditions and checks |
|---|---|
| `sparse` | One known banner port and otherwise closed ports |
| `protocols` | Banner, HTTP 200 with a known Server header, and HTTPS with the fixture certificate fingerprint |
| `silent` | TCP is accepted and held without a response; the result must remain open with a null banner |
| `mixed` | Known open/closed ports and DROP rules for 19000–19003 |
| `scaling-sparse` | Larger port list with one known open port |
| `scaling-open` | Larger list with 64 or 256 independently listening banner ports |
| `scaling-all` | Full-profile scan of ports 1–65535, mostly closed |

The scaling variants belong to the same fifth scenario family. Readiness
checks visit every service concurrently, plus a closed port and every
filtered port. The persistent service process uses a selector instead of one
thread per listener, and does not stop after a fixed connection count.
Listener creation or readiness failure stops the battery before timing.
Service telemetry records per-port accepted connections, errors, and silent
connection occupancy. Large custom workloads must fit the VM's descriptor
limits; failures are reported rather than silently dropping listeners.

The DROP case uses **one named nftables counter per filtered port**. Counters
are reset after readiness and verified to be zero. Each port's counter must
increase during the measured execution. An aggregate positive count is not
sufficient. Counters count packets, including possible retransmissions;
they are not connection-start or packet-rate measurements for Hylianscan.

Hylianscan currently reports open TCP findings only. Refusals and discovery
timeouts are both absent from its findings. The benchmark checks that DROP
ports are absent and were attempted; it does not invent closed, filtered,
timeout, or unknown classifications.

## Profiles and pilot calibration

| Setting | Quick | Full |
|---|---|---|
| Base size | 400 ports | 400 ports |
| Scaling size | 4,096 ports | 4,096 ports plus the 65,535-port case |
| Dense open ports | 64 | 256 |
| Warm-ups per scenario/version | 1 | 2 |
| Fast measured runs | Pilot-selected, 2–7 | 30 |
| Long measured runs | Pilot-selected, 2–3 | 10 |
| Full-port measured runs | Excluded | 5 |

Before measured runs, a pilot executes every scenario/version. Its elapsed
cost includes lab recreation, validation, cleanup, and memory companions.
The quick profile targets 180 seconds for the whole battery and reduces
repetitions when needed, retaining every case and at least two samples.
The target is an estimate, not a deadline: if it is infeasible even with
minimum repetitions, the report says so and coverage is preserved. Pilot and
warm-up samples are retained but excluded from measured statistics.

Defaults use 50 workers, a one-second TCP/probe timeout, IPv4, HTTP probing,
quiet output, and no connection-start cap. The full-port list is compressed
to `1-65535` in the command so it does not exceed exec argument limits.

Examples of deliberate overrides:

```sh
python3 scripts/benchmark.py --benchmark tcp_scan --budget-seconds 240
python3 scripts/benchmark.py --benchmark tcp_scan --fast-runs 5 --slow-runs 2
python3 scripts/benchmark.py --benchmark tcp_scan --profile full --many-open 512 --workers 100
python3 scripts/benchmark.py --benchmark tcp_scan --delay-ms 25 --run-timeout 180
```

Explicit repetition overrides are preserved, even if they exceed the quick
target. `--base-ports`, `--scale-ports`, `--warmups`, `--timeout`, `--max-rate`,
and `--full-runs` are configurable. Measured repetition counts must be at
least two. The full profile always includes all 65,535 ports. Worker/timeout
sweeps are separate invocations, not an automatic Cartesian product.

## What the clocks measure

| Field | Boundary |
|---|---|
| `execution_seconds` | Hyperfine starts the actual Python Hylianscan command after it is inside the scanner namespace and running as the ordinary user; includes Python startup, local target resolution, combined scanning/probing, report construction, and output saving |
| `native_scan_seconds` | Hylianscan JSON's existing discovery-plus-probing duration; excludes CLI startup, target resolution, and output saving |
| `total_sample_seconds` | One execution's preparation, readiness, measurement, validation, and cleanup |
| `total_battery_seconds` | Independent monotonic clock from before preflight/pilots until final cleanup; includes warm-ups, companion executions, checkpoints, and orchestration |

Initial phase timing measures discovery and probing **together**. Separate
discovery/probing fields are null with an unavailability reason. The harness
does not parse decorative terminal output or alter scanner callbacks.

Every primary sample uses a new Hyperfine process, `--shell=none`, one run,
and zero internal warm-ups/hooks. The harness owns warm-ups and preparation.
Measurement tools use `LC_ALL=C`, including GNU Time's numeric output.
This keeps CPU summary fields attributable to that one child and prevents
the Linux `RUSAGE_CHILDREN` peak-memory high-water mark from leaking across
earlier children. Python's standard-library statistics combines the samples.

When Hyperfine cannot export memory, a fresh laboratory executes the same
scenario through GNU Time. It has its own command, output, correctness
check, CPU samples, and peak memory. The report links it with `parent_id` and
marks its source `gnu_time_companion`. It is **not** the memory of the primary
execution, and its elapsed time is excluded from primary timing statistics.
It still contributes to total battery time and pilot cost. Warm-ups do not
need memory companion executions.

Each run has a separate working directory. The CLI receives explicit
filenames and uses its existing `output/` semantics within that directory;
reports are not overwritten across versions or repetitions. The filesystem
and Python bytecode caches remain shared/warm. Readiness warms neighbor
resolution inside each otherwise fresh network lab. No global caches are
flushed.

## Reports and comparison

Defaults save to `output/benchmark/<UTC timestamp>_<unique id>/`. An
`--output-dir` changes the parent, still creating a new unique battery.

The directory contains `report.json`, individual `samples.csv`, statistical
`summary.csv`, `battery.csv`, and `comparison.csv`. The JSON report and
`battery.csv` record the benchmark type separately from the profile.
Each sample directory
contains its configuration, readiness evidence, exact launcher/scan command,
Hyperfine or GNU Time measurements, TXT/JSON scan outputs, logs, per-port
DROP counters, service telemetry, privileged operation log, and `sample.json`.

Validation rejects missing, duplicate, or unexpected open ports, wrong
addresses/scope, inconsistent JSON result views, missing expected evidence,
service failure, nonzero exit, expired execution deadlines, or cleanup
failure. A correctness failure aborts immediately, retains evidence, and
invalidates comparisons even if the candidate was faster. Statistics keep
measured successful samples separate from pilots, warm-ups, and companions.
They include mean, median, minimum, maximum, and sample standard deviation.

Calibrate ordinary variation using two labels for the same checkout first:

```sh
python3 scripts/benchmark.py --benchmark tcp_scan --reference . --candidate .
python3 scripts/benchmark.py --benchmark tcp_scan --reference /path/reference --candidate /path/candidate
python3 scripts/benchmark.py --benchmark tcp_scan --reference /path/reference --candidate /path/candidate --regression-percent 10
```

Both checkouts use the same interpreter. Measured reference/candidate runs
alternate order and never run concurrently. With no configured threshold,
the report shows changes without declaring a performance regression.
An opt-in threshold compares median complete execution time; it is not a
statistical significance test. Choose it after observing reference/reference
variation, including longer runs when the quick profile yields few samples.

Metadata includes commands, effective options, complete port lists, expected
services, commits, Git status, measured-source hashes and diff fingerprint,
interpreter, executable versions, Kali/OS/kernel, CPU/affinity, memory, and
detected virtualization. `--vm-notes` records host load, vCPU/RAM settings,
power settings, and other configuration that the guest cannot discover.
Arbitrary workspace diffs are not copied into reports.

Exit codes: 0 for a completed battery, 1 for failed correctness/lab/tool
checks, 2 for a configured performance regression, and 130 for interruption.
Failure and Ctrl+C retain elapsed battery time and collected artifacts.
Cleanup is owned by Python rather than Hyperfine hooks. Repeated interruption
is ignored only while cleanup is in progress. SIGKILL or VM power loss cannot
be caught; retained checkpoints identify resource names for recovery.

## Validation status and future stages

**Kali acceptance is pending.** Windows localhost checks validate the
persistent services, real dispatcher, report checks, and mocked failure/
interruption cleanup. They do not validate Linux namespace/nftables behavior
or establish a calibrated Kali baseline.

Before declaring the benchmark validated, run quick and full batteries on
Kali (including dense probes and 65,535 ports), confirm each DROP counter,
compare the reference against itself, and exercise Ctrl+C and a failing
measured command. Check the recorded namespace names against `ip netns list`
and verify their absence from `/etc/netns`. The report distinguishes actual
lab execution, Kali execution, and complete battery execution.

Offline checks use Python 3.12 for the repository suite:

```sh
python3.12 -m unittest tests.test_benchmark -v
python3.12 -m unittest discover -s tests -p "test_*.py" -v
python3.12 -m compileall -q hylianscan.py core modules scripts tests
```

Future stages get independent expected results and scenarios: IPv6,
multiple addresses, optional Nmap enrichment/import, real passive binaries,
and DNSx against controlled local DNS. The offline Subfinder/Amass battery
measures orchestration separately from real-binary compatibility/performance
checks. These stages do not become part of the native TCP numbers.

References: [Hyperfine manual](https://github.com/sharkdp/hyperfine/blob/master/doc/hyperfine.1),
[Hyperfine Unix resource measurement](https://github.com/sharkdp/hyperfine/blob/v1.20.0/src/timer/unix_timer.rs),
[nftables counters](https://wiki.nftables.org/wiki-nftables/index.php/Counters),
[Linux namespaces](https://man7.org/linux/man-pages/man8/ip-netns.8.html),
[GNU Time](https://www.gnu.org/software/time/manual/time.html).
