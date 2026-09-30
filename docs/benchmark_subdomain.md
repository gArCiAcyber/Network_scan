# Offline subdomain benchmark

This page documents the existing runner and the revised
[Hylianlab Kali laboratory plan](#hylianlab-kali-laboratory-plan). The plan
below defines the next implementation; it does not describe features already
available. Current commands still use `benchmark.test`.

Run from a source checkout with Python 3.10+; use Python 3.12 for repository
tests. No Subfinder/Amass installation, API credentials, sudo, Hyperfine, or
public targets are needed. Workers block socket creation and DNS resolution.
Only the known provider commands can launch, and they launch local Python
fixtures. DNSx and HTTPx are disabled.

```sh
python3 scripts/benchmark.py --benchmark subdomain
python3 scripts/benchmark.py --benchmark subdomain --profile full
python3 scripts/benchmark.py --benchmark subdomain --reference . --candidate .
python3 scripts/benchmark.py --benchmark subdomain --reference /path/reference --candidate /path/candidate
```

Use `python` instead of `python3` where appropriate on Windows.
`quick` is the default; both profiles validate every execution. Real-binary
and live comparisons are not implemented. Passing `--live` is rejected.

## Workloads and correctness

| Scenario | Expected behavior |
| --- | --- |
| subfinder | 100 unique names from Subfinder alone |
| amass | 100 unique names from Amass alone |
| overlap | 100 per provider, 50 shared, 150 in the union |
| scaling | 10,000 per provider in quick; 100,000 in full; overlapping output and stderr beyond pipe capacity |
| empty | Both providers complete successfully with no names |
| failure-partial | Amass exits 7 after emitting findings; both providers' evidence is saved |
| timeout-partial | Amass emits findings then stalls; the real runner terminates it and preserves partial results |
| invalid-scope | Invalid hostnames, URLs, wildcard entries, the apex, and unrelated domains must not become accepted subdomain findings |

Nonempty fixtures include duplicate names, uppercase/trailing-dot variants,
and ANSI escapes. Fixtures also emit blank lines and non-hostname messages.
Expected sets are generated independently of the production cleaner. The
scope oracle accepts ASCII DNS hostnames (including ASCII punycode labels),
with labels up to 63 characters and a total length up to 253 characters,
strictly below the reserved `benchmark.test` domain. The apex and wildcard
entries are excluded; DNS resolution is not part of validity.

Validation checks exact provider sets, the union, counts, attribution,
sorted/deduplicated output, exact TXT contents, JSON candidates, CLI exit
code, provider status/error reasons, runner result checkpoints, sequential
launch order, and fixture process cleanup. An expected provider failure can
pass its scenario's correctness checks; its time is not eligible for a
successful-discovery performance ranking. Unexpected losses, extra names,
errors, or cleanup failures invalidate the battery's performance comparisons.
All cases continue after a failed correctness check, preserving other evidence.

**Known production defect:** `clean_subdomain()` normalizes output but does
not enforce hostname syntax or domain membership. The current implementation
exports seven invalid/out-of-scope entries in the `invalid-scope` scenario.
The benchmark exposes this behavior without filtering away the evidence or
changing production behavior. Therefore, a complete battery against the
current implementation exits 1. This is a correctness finding, not a failed
benchmark installation. A production validation fix needs its own deliberate
contract, tests, documentation, and exported-evidence review.

## Measurement and comparison

Every execution starts a fresh Python worker which imports the requested
checkout's modules. Only executable resolution, provider process launch,
and the provider timeout are adapted. Hylianscan's real CLI, provider wrappers,
runner, result types, deduplication, source attribution, and writers execute
unchanged. Fixtures verify orchestration, not external-provider CLI compatibility,
API coverage, or Amass 5 graph retrieval.

`execution_seconds` starts immediately before launching the worker and ends
when it exits. It includes worker bootstrap, Python imports, boundary adapters,
fixture subprocesses and their output logging, the passive CLI, its TXT/JSON
exports, and worker cleanup. It is not pure provider time or first-candidate
latency. Fixture preparation, report validation, and harness checkpoint writes
are outside this metric. `total_sample_seconds` includes those operations;
`total_battery_seconds` also includes metadata collection and final reporting.

Reference and candidate use identical fixture data/deadlines and the same
interpreter. Measured order alternates reference/candidate then
candidate/reference. Workload hashes allow equivalence checks. Pilots and
warm-ups are retained but excluded from measured statistics. Correct measured
samples report count, mean, median, minimum, maximum, and sample standard
deviation; failed samples remain in the raw reports. No confidence interval or
statistical-significance claim is made. Failure/timeout scenarios have descriptive
statistics but are excluded from performance rankings.

The existing pilot budget/repetition policy is reused: quick starts with seven
fast or three timeout repetitions, full with thirty fast or ten timeout
repetitions. Quick can reduce unoverridden counts to at least two to estimate
its 180-second battery target; this is not a hard deadline. Warm-ups default
to one for quick and two for full. All correctness cases remain present.

```sh
python3 scripts/benchmark.py --benchmark subdomain --fast-runs 2 --slow-runs 2 --warmups 0
python3 scripts/benchmark.py --benchmark subdomain --profile full --fast-runs 2 --slow-runs 2 --warmups 0
python3 scripts/benchmark.py --benchmark subdomain --provider-timeout 3 --run-timeout 120
```

`--provider-timeout` defaults to 2 seconds per provider and applies to all
fixtures. Very short deadlines can invalidate runs before a subprocess emits
its findings. `--run-timeout` defaults to 120 seconds per worker. TCP port,
worker, packet-delay, and scan-rate settings do not alter the passive workloads.

There is no default performance-regression threshold. Calibrate using the
same checkout as reference and candidate before choosing
`--regression-percent`. Observed medians remain inspectable even when a
correctness defect invalidates a comparison; invalid comparisons never produce
a regression verdict. Existing production scope defects must be resolved
before declaring a passing full baseline.

## Reports and interruption

Each battery gets a new directory under
`output/benchmark/<UTC timestamp>_<unique id>/`, or under `--output-dir`.
Files are never shared across samples or checkouts.

- `report.json`: options, environment/interpreter, runtime source hashes,
  Git revision/status, harness hashes, scope/timing policy, calibration,
  individual samples, validation status, statistics, and comparisons.
- `samples.csv`, `summary.csv`, `comparison.csv`, `battery.csv`: flattened
  observations and statistics. Samples include commands, workload hashes,
  provider statuses, scoped counts, overlap, and exclusive contributions.
- Per-sample directories: fixed provider inputs/expected sets, emitted stdout
  and stderr logs, requested/executed command ledger, runner result checkpoints,
  worker log/cleanup record, actual passive TXT/JSON, and `sample.json`.

Inputs and running sample records are checkpointed before launch. Completed
provider results are checkpointed before the CLI finishes the full workflow.
Failures and caught interrupts retain collected files and final status. Raw
fixture logs can survive an interruption even when the production runner does
not return partial findings; they are not relabeled as accepted CLI results.
The worker reaps its own fixtures. On cancellation/deadline, the harness first
requests interruption, then escalates to process-group/tree termination.
SIGKILL, forced termination, or power loss cannot guarantee finalization.

Exit codes: 0 for a correct completed battery, 1 for correctness/tool/worker
failure, 2 for an eligible configured regression, 130 for caught interruption.

## Validation status

Local validation on Windows with Python 3.12 passed all 360 repository tests,
including real subprocesses, partial results, cancellation cleanup, and
isolated source checkouts. The default quick battery completed with 68 samples.
A full-profile reference/candidate battery with two measured repetitions and
no warm-ups completed with 48 samples; its scaling case preserved all 150,000
expected unique names. Both batteries failed only the known `invalid-scope`
case and correctly invalidated performance comparisons.

Linux/Kali execution and real external-provider compatibility are not verified
by these checks. Live source variability, credentials, Amass 5 graph behavior,
first-candidate timing, DNSx, CPU, and memory are deferred.

```sh
python3.12 -m unittest tests.test_benchmark_subdomain tests.test_benchmark -v
```

## Hylianlab Kali laboratory plan

The revised target is a fictitious company, **Hylianlab**, using the canonical
domain **`hylianlab.test`** throughout inputs, expected sets, provider commands,
and the future DNS zone. `.test` and its descendants are reserved for special
use in the [IANA registry](https://www.iana.org/assignments/special-use-domain-names).
The generated names are laboratory data; websites and certificates are not
required for the integration battery.

All laboratory batteries will run in the Kali VM. Keep the portable Python
fixture checks for development, while recording Kali execution separately.
Subfinder uses passive online sources according to its
[official overview](https://docs.projectdiscovery.io/opensource/subfinder/overview).
Consequently, creating local DNS records alone does not make this dataset
discoverable through those sources. Provider input data and DNS answers need
separate fixtures.

### Implementation order and current evidence

| Stage | Deliverable and acceptance gate | Current status |
| --- | --- | --- |
| 1. Dataset and integration | Deterministic Hylianlab manifests, provider executables, exact set/attribution checks, 1k/10k/100k workloads | Extend existing fixtures; Hylianlab dataset and Kali execution not implemented/verified |
| 2. Faults and retention | Heavy duplicates, paced/burst output, deterministic partial results, actual SIGINT, cleanup and saved-evidence checks | Empty/failure/timeout fixtures exist; paced streams and exact interrupted CLI reports are missing |
| 3. Measurements and comparison | Separate timing stages, calibrated repetitions, version comparison, validated optional memory collection | End-to-end timing, A/B ordering and JSON/CSV exist; stage timing and passive memory measurement are missing |
| 4. Real providers | Pinned Subfinder/Amass against proven local source services, direct/integrated comparisons | Local source compatibility, passive Amass configuration and graph retrieval are not verified |
| 5. DNSx | Controlled local DNS, independent resolution oracle and metrics | Production DNSx integration exists; this laboratory battery is not implemented/verified |

Reuse `scripts/benchmark.py` for profiles, metadata, isolated checkouts,
repetitions and report persistence, and evolve `scripts/benchmark_subdomain.py`
for this dataset. Do not create a second benchmark orchestration framework.
Keep providers sequential, matching the production flow. Reviewers must check
each stage against the actual CLI, runners and writers before marking it done.

### Dataset and independent expected results

Generate valid names with Python's standard library, including simple and
nested labels such as `api.hylianlab.test`, `mail.hylianlab.test`,
`server000001.hylianlab.test`, and `api.dev.europa.hylianlab.test`. Fix the
generator version, seed, ordering and substitutions so each manifest has an
exact number of unique names. No `megacorp.test` examples remain in the new
dataset. Include case/trailing-dot variants and ASCII punycode without changing
the canonical expected names.

For a union of N names, use 70% in Subfinder, 60% in Amass and 30% shared:

| Union | Subfinder | Amass | Shared | Subfinder only | Amass only |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 700 | 600 | 300 | 400 | 300 |
| 10,000 | 7,000 | 6,000 | 3,000 | 4,000 | 3,000 |
| 100,000 | 70,000 | 60,000 | 30,000 | 40,000 | 30,000 |

The volume label means **unique names in the final union**, unlike the current
scaling fixture's per-provider size. Save the canonical union, provider sets,
source mapping, rejected entries, emission order and partial prefixes before
execution. Hash these artifacts and record the hashes in every sample. The
oracle comes from the manifest and independent hostname/scope rules; it must
not call the production cleaner or derive the expected set from actual output.

The accepted set contains strict descendants of `hylianlab.test`, with valid
ASCII DNS labels up to 63 characters and total names up to 253 characters.
The apex, wildcard notation, URLs, empty labels, invalid hyphens, oversized
names and other domains are rejected. Legitimate DNS wildcard responses belong
to the later resolution battery. Validate both missing and unexpected names,
per-provider membership, the exact union and source attribution, sorting,
deduplication, counts, completion/error states, and exact TXT/JSON contents.

### Local provider executables and difficult scenarios

In Kali, supply local executables through the existing `--subfinder-path` and
`--amass-path` controls. They accept the expected domain and provider arguments,
validate them, and stream their manifest data through real stdout/stderr pipes.
This also exercises executable resolution and process launch. The Hylianscan
CLI, runner, parser, result types, merge and writers remain the measured flow.
Any required harness adapter must be recorded and must not alter findings or
completion status. The current portable launch adapter can remain for its
existing checks, with results labeled separately.

| Scenario family | Controlled input and required result |
| --- | --- |
| Provider coverage | Subfinder only, Amass only, and both; exact provider sets and union |
| Throughput | Immediate output, large flushed bursts, and fixed-rate batches as separate scenarios |
| Duplicates | Baseline and 10x raw name occurrences with the same canonical union; duplicates within and across providers |
| Parsing and scope | Case, ANSI, CRLF, blanks, final line without newline, dotted diagnostic messages, invalid names, apex and scope traps |
| Empty output | Successful empty provider versus a failed provider with no findings; distinct states |
| Stream pressure | stdout and stderr beyond pipe capacity, including interleaved diagnostics; bounded completion without deadlocks |
| Failure | Nonzero exit and abrupt termination after a known prefix, plus failure before any name and executable-launch failure |
| Timeout | Known prefix then a stall, plus a stall before the first result; preserve exactly the expected partial set |
| Cancellation | Real SIGINT after a confirmed prefix, between providers, and during saving; explicit interruption status, retained evidence and no surviving children/readers |
| Report failure | Unwritable output or an injected writer error; no success verdict or silent replacement of earlier evidence |

Use bounded deadlines derived from the scenario's fixed emission schedule,
plus a recorded margin. Slow output tests orchestration and responsiveness;
its intentional sleep must not be reported as processing overhead. Keep the
emitter implementation and logging identical for reference and candidate.

For faults and SIGINT, distinguish **emitted**, **received by the runner**,
**accepted**, and **saved** names. A subprocess flush alone does not prove that
the runner consumed its output. Use a synchronization barrier after the runner
has accepted the manifest's known prefix, hold remaining output, then trigger
the fault. Observation records events; it must not repair or synthesize
production results. The expected partial union includes earlier completed
providers plus that accepted prefix, with exact source attribution.

The current cancellation test retains emitted fixture logs and a completed
provider checkpoint. It does not establish preservation of the interrupted
provider in Hylianscan's final TXT/JSON: `run_passive_provider()` re-raises
`KeyboardInterrupt`, and `run_passive_subdomain_discovery()` writes reports
after providers return. This retention requirement may need a production fix.
Likewise, the existing scope failure remains a real correctness failure.
Handle required production changes deliberately, with compatibility review and
regression tests; never make the benchmark pass by filtering its evidence.

### Load progression, timing and version comparison

`--benchmark subdomain --profile quick|full` remains the interface, with quick
as the default. The revised quick profile covers 1k and 10k unions plus every
correctness/fault family using bounded inputs. Full adds the 100k union, heavier
duplicates and longer paced streams. DNSx and real-provider execution need
explicit separate selections and must not become side effects of `full`.

Increase beyond 100k only after the preceding workload passes correctness and
cleanup checks and its resource usage fits recorded VM limits. Larger loads
must be explicitly selected and bounded; no automatic unbounded scaling.
Record vCPU/RAM limits, OS/kernel, Python, filesystem/output device, VM notes,
and workload duration/byte volume. Stop an infeasible case cleanly and report
why it did not complete.

Measure these intervals with a monotonic clock and explicit boundaries:

- End-to-end execution: worker launch through exit, using the current definition.
- Per provider: process launch through stream drain and collection completion.
- First candidate: process launch to the runner's first accepted valid in-scope
  name; record empty/interrupted-before-result as unavailable, never zero.
- Merge/sort, TXT write, and JSON build/serialization/write as separate stages.
- Total sample and battery time, including preparation, validation and cleanup.

These stages can overlap, especially provider output and consumption. Do not
sum overlapping intervals or subtract emitter delay and call the remainder
pure processing time. Writer timings must state whether they cover encoding,
file close and cached filesystem writes; they do not establish durable disk
latency. A claim that saving dominates requires those stage observations.

Begin with stdlib timing. Add a separate memory/resource measurement pass only
after validating its collector with known allocations and child processes.
Record the method, units, sampling interval where applicable, included PIDs,
and observer overhead. Distinguish a process's maximum RSS from aggregate
process-tree or cgroup memory; do not label one as the other. If collection is
unavailable or unreliable, save `null` with a reason. Hyperfine is optional for
cross-checking end-to-end timing, not a required dependency. Assetfinder adds
no coverage needed for these initial two-provider correctness sets.

Run a same-revision A/A calibration in Kali before choosing regression limits.
Reference and candidate receive identical manifests, emission schedules,
deadlines, interpreter and recording configuration. Alternate A/B then B/A,
keep warm-ups separate, retain individual samples and report variation.
Keep caches and persistent provider state equivalent or reset them explicitly.
Do not choose a default percentage from a single run.

Track scenario correctness separately from the expected process outcome.
A deliberate failure/timeout/SIGINT may pass its **fault scenario** only when
partial evidence, status and cleanup match the oracle. Its timing is excluded
from successful-discovery rankings. Missing or extra findings invalidate
performance comparisons, including when the faulty run is faster.

### Real-provider compatibility battery

First pin the installed Subfinder and Amass versions, capture actual help,
commands, binary hashes, source selection, configuration hashes, credential
availability without secret values, limits and ordering. Use fresh Amass
storage per sample. Verify passive behavior and output retrieval for that
exact Amass version, including graph queries when required; the current
`enum -passive` fixture does not establish Amass 5 compatibility.

Prove one controlled source for each real provider before expanding source
coverage. Check source code and local help for endpoint/proxy/config support,
then validate the source's request and response contract against a local
service. A DNS resolver override alone is insufficient. Subfinder's documented
[source, configuration and proxy controls](https://docs.projectdiscovery.io/opensource/subfinder/usage)
do not establish that every source can use an arbitrary local endpoint. If a
provider needs a source patch, custom build or TLS trust adaptation, record it
and label the result as an adapted-provider test. Feasibility remains **not
verified** until this experiment succeeds.

Compare Subfinder direct versus integrated, Amass direct versus integrated,
and both direct versus both integrated. Joint execution means sequential
Subfinder followed by Amass in both cases; merging and saving in the direct
baseline must follow the same declared output contract. Record provider-only
and full-flow boundaries separately. Where Amass requires graph extraction,
include that retrieval in both full-flow measurements and define the first
candidate at the receiving boundary after extraction.

Local services and providers remain confined to laboratory networking, with
external traffic denied and independently checked. Public-source runs would
need a separate explicit choice and authorized real targets; they cannot use
the fictional dataset as a known discovery oracle. Source variability,
credentials, caches and throttling can prevent attributing a timing difference
to Hylianscan, so such results must be labeled descriptive when controls fail.

### Separate DNSx battery

Use the same candidate manifest, plus an independent map of expected DNS
responses and resolved names. Start with a local authoritative CoreDNS zone
using its [file plugin](https://coredns.io/plugins/file/); its
[template plugin](https://coredns.io/plugins/template/) can define error
response codes. Add controlled delay/loss with isolated lab network rules
only when those scenarios are exercised. Server and fault-injection behavior
must be validated independently before using them as an oracle.

Cover A-only, AAAA-only, dual-stack, CNAME chains, NXDOMAIN, NOERROR without
address records, SERVFAIL, delay/timeouts, retry limits, and a wildcard subtree.
Preserve all discovered candidates separately from address-confirmed results.
Wildcard DNS can resolve a name without proving it was discovered or explicitly
exists in the zone; validate filter-on and filter-off behavior separately.
Use explicit local resolvers and fixed rates/concurrency/retries. Verify flags
against the pinned binary: the
[DNSx documentation](https://docs.projectdiscovery.io/opensource/dnsx/usage)
documents resolver and wildcard controls, but does not verify this project's
exact command against the installed release.

Record DNS query/response logs, retries, configuration, candidate/resolved sets,
and resolution-stage duration independently from passive discovery. Reset or
label caches and block forwarding to public resolvers. HTTPx, active TCP scans
and website creation remain outside these batteries.

### Reports and completion gate

Extend the existing JSON/CSV reports with manifest/seed hashes, raw line and
byte counts, emitted/received/accepted/saved counts, stage observations,
resource-method availability, expected/observed outcomes and correctness.
Preserve commands, versions, Git state, environment, individual repetitions,
missing/unexpected names, provider attribution, raw logs and actual TXT/JSON.
Checkpoint before launch and after completed stages; retained raw output must
be clearly distinguished from saved Hylianscan findings after interruption.

A stage is complete only after its oracle checks, actual fault execution,
cleanup checks and relevant regression tests pass in Kali. Reports may state
that 100k candidates were processed correctly or that interrupted findings
were saved only when the exact sets support those claims. Every unsupported
measurement or compatibility assumption remains **not verified**. Current
Windows results above validate the existing runner, not the proposed Kali lab.
