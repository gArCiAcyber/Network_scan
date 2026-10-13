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
least two. The full profile includes all 65,535 ports by default. Worker/timeout
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

**Selected Kali acceptance was recorded on 2026-10-06/07**, at product revision
`5b0585219a6dcbf9daaa07fd2bd5ebf9021b86d2`: quick/full TCP cases, dense probes,
65,535 ports, per-port DROP checks, failure/SIGINT cleanup and alternating A/A.
Five full-port A/A pairs showed a +1.75% median difference for identical code;
protocol pairs ranged from -11.86% to +22.86%. An independent 2026-10-08 UTC
campaign increased full-port pairs to twelve and used twenty protocol pairs,
starting with the candidate and alternating measured order. Identical product
hashes produced median changes of -0.18% and +0.49%, respectively; individual
pairs still ranged from -4.41% to +2.74% and -9.19% to +4.00%. Host activity was
observed but uncontrolled. These are variability observations, not regression
thresholds; no universal threshold is enabled.
Session evidence is retained separately under `output/validation/` and is not
distributed as repository fixtures. Windows checks remain separate.

Before declaring the benchmark validated, run quick and full batteries on
Kali (including dense probes and 65,535 ports), confirm each DROP counter,
compare the reference against itself, and exercise Ctrl+C and a failing
measured command. Check the recorded namespace names against `ip netns list`
and verify their absence from `/etc/netns`. The report distinguishes actual
lab execution, Kali execution, and complete battery execution.

## Additional verification and bounded campaigns

Every execution now reads the saved `scan.txt`, checking exact port membership,
duplicates, per-port banner/status evidence and ANSI escapes against the service
configuration. Legitimate TLS explanation bullets are not finding rows.
TXT and JSON are independently checked; matching two reports is insufficient.

`--min-free-gib` reserves 1 GiB by default before each execution and records
available bytes. It does not estimate the entire campaign or cap a growing file.
Choose a campaign that fits the disk; previous 100k evidence campaigns generated
about 12 GiB. No previous evidence is deleted automatically.

Use `--tcp-scenario` repeatedly for selected TCP cases. `--first-variant`
chooses the initial measured order; later pairs alternate. `pairs.csv` preserves
individual pair differences and order without changing the opt-in median verdict.
Start a new campaign with the opposite initial order, fixed VM/host conditions,
and more full-port pairs before configuring thresholds. Correctness failures
invalidate comparisons.

```sh
python3.12 scripts/benchmark.py --profile full --reference . --candidate . \
  --tcp-scenario protocols --tcp-scenario scaling-all --full-runs 20 \
  --first-variant candidate
python3.12 scripts/benchmark.py --tcp-scenario scaling-open --many-open 256 --workers 100 --resources
python3.12 scripts/benchmark.py --tcp-scenario mixed --drop-ports 64 --timeout .2 --resources
python3.12 scripts/benchmark.py --tcp-scenario protocols --delay-ms 10 --resources
python3.12 scripts/benchmark.py --tcp-scenario silent --silent-listeners 32 --resources
python3.12 scripts/benchmark.py --profile full --tcp-scenario scaling-all --full-open 64 --resources
```

`--resources` enables separately identified Linux companions even if Hyperfine
exports memory. They record waited-child user/system CPU, `ru_maxrss` in bytes,
sampled process-tree RSS/fd/process peaks at 20 ms intervals, owned process
births, cleanup and interface packet/byte deltas. RSS sums can count shared
pages repeatedly; short children and peaks between observations may be missed.
`ru_maxrss` is the largest waited-child high-water mark, not simultaneous tree
memory. Resource execution time is excluded from primary time statistics.
Interface deltas cover all namespace traffic during the companion; the dedicated
TCP scanner namespace excludes readiness and other batteries. Record latency,
workers, listeners, DROP count, timeout and traffic rather than inferring cost
from finding count. Sweeps remain separate bounded invocations, not automatic
Cartesian products. No scanner traffic or defaults change.

The selected 2026-10-08 resource campaign completed eleven TCP configurations
across two finite sessions, covering delay, workers, listeners, silent services
and DROP-heavy timeouts. The final session closed the three interrupted cases:
64 DROP ports at .2/1-second timeouts and 65,535 ports with 64 listeners. Each
had one pilot and two measured executions, with separate resource companions;
all TXT/JSON, per-port DROP and cleanup checks passed. Primary medians were
0.524, 2.129 and 12.395 seconds. One of the two measured full-port companions
could not inspect a PID and retained unknown tree RSS/descriptors/processes;
CPU, waited-child maximum RSS and traffic remained available. This is selected
functional/resource evidence, not a calibrated optimization result. All 36
recorded namespaces and their configurations/interfaces were absent afterward.
Raw evidence and final checks are retained under
`output/validation/benchmark_completion_20261008_181222/`.

Offline checks use Python 3.12 for the repository suite:

```sh
python3.12 -m unittest tests.test_benchmark -v
python3.12 -m unittest discover -s tests -p "test_*.py" -v
python3.12 -m compileall -q hylianscan.py core modules scripts tests
```

`--resources --diagnostic-profile` adds `cli-stages.json` and `cli-stages.prof`
to TCP resource companions. Markers cover imports, resolution, native scanning,
terminal output and report construction/persistence without changing quiet
output. Nested spans overlap. Time outside the wrapper markers remains
unattributed; profiled companion timings are excluded from primary pairs.

Future stages need independent expected results for IPv6, multiple addresses,
and optional Nmap enrichment/import. Maintained [real-provider and DNSx
acceptance cases](benchmark_providers.md) complement the offline Subfinder/Amass
orchestration battery. Their observations remain separate from native TCP timings.

References: [Hyperfine manual](https://github.com/sharkdp/hyperfine/blob/master/doc/hyperfine.1),
[Hyperfine Unix resource measurement](https://github.com/sharkdp/hyperfine/blob/v1.20.0/src/timer/unix_timer.rs),
[nftables counters](https://wiki.nftables.org/wiki-nftables/index.php/Counters),
[Linux namespaces](https://man7.org/linux/man-pages/man8/ip-netns.8.html),
[GNU Time](https://www.gnu.org/software/time/manual/time.html).
