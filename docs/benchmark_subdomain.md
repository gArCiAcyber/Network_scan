# Hylianlab offline subdomain benchmark

The laboratory uses the fictitious domain **`hylianlab.test`** and deterministic
provider data. It exercises Hylianscan's real CLI, executable resolution,
version/help checks, provider execution, parsing, scope validation,
deduplication, attribution, and TXT/JSON exports. No installed Subfinder or
Amass, source credentials, websites, or public targets are required. DNSx,
HTTPx, and active TCP scanning are not run.

Run from a source checkout with Python 3.10+; use Python 3.12 for repository
tests. `quick` is the default. Deliver and verify the 1k case first, then
increase the load:

```sh
python3 scripts/benchmark.py --benchmark subdomain --scenario baseline-1k
python3 scripts/benchmark.py --benchmark subdomain --scenario baseline-10k
python3 scripts/benchmark.py --benchmark subdomain --profile full --scenario baseline-100k

# Complete correctness batteries
python3 scripts/benchmark.py --benchmark subdomain
python3 scripts/benchmark.py --benchmark subdomain --profile full
```

Use `python` instead of `python3` where appropriate on Windows. Repeat
`--scenario` to select several scenarios available in the chosen profile.
`baseline-100k` requires `full`; unknown scenarios are rejected. Neither
profile invokes real external providers. `--live` is not implemented.

## Reused production fixes and scope policy

Before extending the laboratory, the implementation reused the corrections
from `fix/passive-subdomain-enum` at
`284a07111f90a8714dbc8b8e7fb6e0a3045f8a5e`. See the
[provider implementation](../modules/subdomain.py),
[passive CLI](../hylianscan.py), and
[compatibility policy](provider_compatibility.md). These corrections supply
hostname/domain validation, current provider version/flag handling,
file-backed output collection, checkpoints, and interrupted-result retention.
The benchmark observes their output rather than replacing those behaviors.

The accepted scope includes **the base domain and its descendants**. The apex
`hylianlab.test` is one canonical member of each dataset and counts toward its
N-name union. This matches `scoped_subdomain()`; `clean_subdomain()` only
normalizes text. Wildcard notation, URLs, empty labels, invalid hyphens,
underscores, oversized names, and unrelated domains are rejected. Valid
canonical names use ASCII DNS labels of at most 63 characters and total length
at most 253 characters, including ASCII punycode. Case, terminal escapes, and
trailing-dot variants must normalize to the same expected names.

The earlier `benchmark.test` fixture and its seven-entry scope failure are
superseded. They are not the acceptance policy or expected outcome of this lab.

## Deterministic datasets and independent oracle

[The generator](../scripts/benchmark_subdomain_data.py) creates exactly 1,000,
10,000, or 100,000 canonical names. It mixes simple names such as
`api.hylianlab.test` with hierarchical names such as
`api.dev.europa.hylianlab.test`, and includes punycode and label/total-length
boundaries. Generator version 1 uses seed 0 as its numeric identifier offset;
it does not use a random-number generator. Tests pin deterministic SHA256
digests for all three datasets.

For the two-provider baseline, N means **unique names in the final union**:

| Union | Subfinder | Amass | Shared | Subfinder only | Amass only |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 700 | 600 | 300 | 400 | 300 |
| 10,000 | 7,000 | 6,000 | 3,000 | 4,000 | 3,000 |
| 100,000 | 70,000 | 60,000 | 30,000 | 40,000 | 30,000 |

Provider-only cases use their respective subsets, rather than claiming the
whole union. Empty and fault scenarios have their own expected sets.

Before launch, each sample saves `dataset.json`, `fixture.json`, per-provider
inputs, and `expected.json`. They contain the canonical union, provider
memberships, source map, rejected inputs, emission schedule, and expected
partial results. `workload_sha256` fingerprints the scenario manifest and
provider inputs/expectations. Harness and source hashes are also recorded.
The oracle is independent of production parsing: it neither imports the
production cleaner nor derives expected findings from actual provider output.

Every sample checks exact provider sets and union, missing/unexpected names,
source attribution, sorted/deduplicated results, counts, completion/error
states, version observations, CLI exit code, and exact saved TXT/JSON content.
It also checks the production accepted-name journal, sequential launch order,
and fixture cleanup. A fast execution that loses names fails correctness and
invalidates performance comparisons.

## Provider executable contracts

[Local executable fixtures](../scripts/benchmark_subdomain_provider.py) emulate
Subfinder 2.16.0, Amass 4.2.0, and Amass 5.0.0. They validate the requested
domain, version/help commands, required switches, repeated/unknown options,
and configuration paths. Hylianscan performs its real startup compatibility
checks. The reported versions describe **simulated contracts**, not installed
provider binaries or proven online-source compatibility.

On POSIX, sample-local executable files are passed through the real
`--subfinder-path` and `--amass-path` controls. On Windows, the same paths are
validated, then a recorded launch adapter invokes the Python fixture script.
That adapter does not alter findings or provider statuses. Windows cleanup
allows process-tree termination only for owned fixture PIDs.

Amass 4 supplies graph-style FQDN records. Amass 5 follows the production
`engine` → `enum -passive` → `subs -names` flow with a fresh passive config
home and retained simulated graph. Its fixture engine exposes only the
readiness query on `127.0.0.1:4000/graphql`; worker connections and name lookup
are guarded against other destinations. Amass 5's unsafe `enum -h` path is
rejected. An existing service on port 4000 prevents the isolated run from
starting; the laboratory must not stop a service it does not own.

Provider stdout/stderr remain real subprocess streams. The current production
runner redirects them to temporary files and reads them incrementally, so
stream-pressure cases stress its file-backed collection and drain behavior,
rather than a reader-thread/pipe implementation.

## Scenario coverage

`quick` includes the 1k matrix and `baseline-10k`. `full` additionally includes
`baseline-100k`, `duplicates-100k`, and `gradual-100k`.

| Scenarios | Input and acceptance condition |
| --- | --- |
| `baseline-1k`, `baseline-10k`, `baseline-100k` | Exact 70%/60%/30% memberships and the full N-name union |
| `subfinder-1k`, `amass4-1k`, `amass5-1k` | Exact individual provider subset and its supported output contract |
| `duplicates-1k`, `duplicates-100k` | 10x raw name occurrences with unchanged unique findings and attribution |
| `invalid-scope` | Invalid/external names, wildcard/URL/suffix traps, formatting variants and dotted diagnostics; only canonical scoped names survive |
| `gradual-1k`, `gradual-100k` | Fixed-size flushed batches with a recorded delay between batches |
| `bursts-1k` | Larger flushed bursts, kept separate from gradual delivery |
| `stream-pressure` | Heavy duplicate output plus stderr exceeding ordinary pipe capacity; bounded completion and exact findings |
| `empty` | Both providers succeed without findings |
| `failure-partial`, `abrupt-partial`, `failure-empty` | Deliberate nonzero or abrupt exit; exact partial or empty saved findings and failed status |
| `timeout-partial`, `timeout-empty` | A known prefix, or no findings, followed by a stall; exact saved partial results and timed-out status |
| `sigint-subfinder`, `sigint-amass` | Actual SIGINT after an accepted prefix; exact saved partial sets, attribution, interrupted status and process cleanup |
| `sigint-save` | Actual SIGINT immediately before the second TXT checkpoint write; verify the recovered saved evidence |
| `writer-error` | Inject an error before the second TXT checkpoint write; verify the earlier actual TXT/JSON snapshot and the complete accepted-name journal |

Nonempty inputs also include case/trailing-dot variants and ANSI escapes.
Line framing covers CRLF, blanks, diagnostic messages, and a final record
without a newline. Gradual and burst delays are part of the workload and must
not be described as Hylianscan processing overhead.

SIGINT is triggered by `signal.raise_signal(SIGINT)` inside the worker after
the runner's accepted-name callback reaches the manifest's fixed prefix and
the emitter confirms readiness. It is a real signal, not a guessed elapsed
delay or a fabricated `ProviderInterrupted` result. Amass 5 findings become
accepted when the retained graph is retrieved. Earlier completed providers
remain in the partial union; providers skipped after cancellation remain
explicitly skipped.

Validation distinguishes emitted records, parsed records received by the
runner, accepted unique names, journaled names, and names actually saved in
TXT/JSON. Raw fixture logs alone cannot establish interrupted-result
preservation. The writer fault occurs before the second write begins: it
does not prove atomic report replacement or recovery from arbitrary mid-write
failures. SIGKILL, forced termination, and power loss cannot guarantee report
finalization.

`sample.status = completed` means its oracle passed. The worker may correctly
exit 1 for a deliberate failure/timeout or 130 for a deliberate SIGINT.
Fault cases are excluded from successful-discovery performance rankings.
Unexpected missing evidence, exit codes, status, scope, or cleanup failures
produce a failed sample and retain its artifacts. The remaining battery cases
continue after a failed correctness check.

## Timing, repetitions, and version comparison

The existing benchmark helpers supply profiles, pilots, repetitions, isolated
checkouts, metadata, comparison, and JSON/CSV persistence. Providers remain
sequential. Reference and candidate receive identical fixtures and schedules,
deadlines, interpreter, and observations; measured order alternates A/B then
B/A. Fresh sample directories isolate provider and report state.

```sh
python3 scripts/benchmark.py --benchmark subdomain --reference /path/reference --candidate /path/candidate
python3 scripts/benchmark.py --benchmark subdomain --scenario baseline-1k --reference . --candidate .
python3 scripts/benchmark.py --benchmark subdomain --fast-runs 2 --slow-runs 2 --warmups 0
python3 scripts/benchmark.py --benchmark subdomain --provider-timeout 30 --run-timeout 120
```

`--provider-timeout` defaults to 30 seconds per selected provider, including
real startup compatibility checks. Timeout scenarios deliberately use the
smaller of the configured budget and three seconds. Very short overrides can
expire during startup and fail the partial-result oracle. `--run-timeout`
defaults to 120 seconds for the whole worker, including fixture execution,
saving, and cleanup. TCP-specific port/rate/worker settings do not change
passive workloads.

Quick begins with seven fast or three timeout repetitions, reducing
unoverridden counts to at least two when its pilot estimates exceed the
180-second target. The target is an estimate, not a hard deadline. Full begins
with thirty fast or ten timeout repetitions. Warm-ups default to one for quick
and two for full. `--fast-runs`, `--slow-runs`, and `--warmups` override those
choices; measured counts must be at least two. Pilots and warm-ups are retained
but excluded from measured statistics.

The monotonic timing observations have these boundaries:

| Observation | Boundary and limitation |
| --- | --- |
| `execution_seconds` | Worker launch through exit; includes imports, adapters, fixtures, evidence logging, CLI reports and worker cleanup |
| Runner checkpoints | Each real runner invocation, including compatibility/version commands, stream drain and collection; production provider elapsed fields retain their own boundaries |
| `first_candidate_seconds` | Discovery/enumeration process launch to the first accepted-name callback; Amass 5 includes waiting for graph retrieval; unavailable results are `null` |
| `merge_seconds` | Aggregate time in the actual merge helper across checkpoints |
| `txt_write_seconds` | Aggregate actual TXT-writer calls, including file close; cached filesystem writes do not establish durable-disk latency |
| `json_write_seconds` | Aggregate JSON report helper calls, including document construction, serialization and file write |
| `json_build_seconds` | Document-construction subset of JSON report time; do not add it to `json_write_seconds` |
| `total_sample_seconds`, `total_battery_seconds` | Include preparation, validation, reporting and cleanup outside the execution metric |

Intervals may overlap and writer totals include multiple checkpoints. Do not
sum them as independent phases or subtract emitter sleep and call the
remainder pure processing time. Saving-dominates claims require these stage
observations, not just end-to-end duration.

Memory is `null` with an explicit reason because no passive process-tree
collector has been validated. CPU measurement, Hyperfine, and Assetfinder are
not needed for this battery. Add a separate resource pass only after verifying
its units, child-PID coverage, observer overhead, and known allocations.

Successful measured samples report count, mean, median, minimum, maximum, and
sample standard deviation. No statistical-significance claim or default
regression percentage is made. Run same-revision A/A calibration in Kali
before setting `--regression-percent`; that option requires a reference.
Any correctness failure invalidates the battery's performance comparisons.

## Reports and retained evidence

Each battery creates a new directory under
`output/benchmark/<UTC timestamp>_<unique id>/`, or under `--output-dir`.
Existing evidence is not reused or overwritten across samples.

- `report.json`: options, domain/scope/timing policy, reused fix revision,
  environment and interpreter, source/Git/harness hashes, calibration,
  individual samples, validations, statistics and comparisons.
- `samples.csv`, `summary.csv`, `comparison.csv`, `battery.csv`: individual
  outcomes, timings, counts, attribution contributions, validation/cleanup
  errors, commands, workload hashes, status and variation.
- Each sample: dataset/input/expected manifests, sample-local executables,
  `provider-commands.jsonl`, `launches.jsonl`, per-command stdout/stderr logs,
  readiness records, `runner-results.json`, `worker.json`, `worker.log`,
  `sample.json`, and retained simulated Amass graph/configuration.
- Actual product evidence: `evidence/subdomains.txt`, the observed-name TSV
  journal and provider diagnostic log beside it, and `output/passive.json`.

Running records and inputs are checkpointed before launch; observed runner
results and actual product checkpoints are retained as execution progresses.
Failures and caught harness interruption preserve the collected directory.
Workers stop and reap owned fixtures; the outer harness escalates bounded
cancellation to process-group/tree termination when necessary. The launch
ledger records process birth identities so cleanup can finish even after a
worker exits, without terminating a different process that reused a PID.

Exit codes for the **battery** are 0 when all selected oracles pass, 1 for
correctness/tool/worker failure, 2 for an eligible configured performance
regression, and 130 for interruption of the harness itself. Deliberate fault
scenarios can therefore pass a battery even when their worker exits 1 or 130.

Environment metadata records platform, kernel, architecture, CPU count,
interpreter and working directory. Use `--vm-notes` to record vCPU/RAM limits,
host details, filesystem/output device, and other guest-invisible settings.
No claim that the host has suitable resource limits follows from a pass.

## Validation status

Windows development checks with Python 3.12 passed `baseline-1k` first, then
`baseline-10k`, and finally `baseline-100k`, each with one pilot and two
measured samples, no warm-ups. Their TXT/JSON unions contained exactly 1,000,
10,000, and 100,000 expected unique names. Attribution, provider contracts,
accepted journals, and process cleanup also passed. Full-profile stress cases
`duplicates-100k` and `gradual-100k` also passed one pilot and two measured
samples each, preserving exactly 100,000 final names. The complete 1k fault
matrix passed integration checks against the actual saved reports and
accepted journals, including SIGINT and provider process cleanup.
The default quick battery completed all 20 scenarios and 80 retained samples
(pilot, warm-up, and two measured runs per scenario) with no correctness or
cleanup failures. It took 228.5 seconds on this Windows host; its pilot marked
the 180-second target infeasible while preserving every scenario and the
minimum measured repetition count. This is a local correctness check, not a
Kali performance baseline.
The full Python 3.12 unittest suite passed 420 tests with one POSIX-specific
skip. Additional checks passed for compilation, both CLI help commands,
Python 3.10 syntax, and whitespace. An abrupt-worker-loss regression verifies
the outer cleanup path separately from graceful cancellation.

**Linux/Kali execution is not verified.** This workspace is on Windows and
does not provide a Kali VM or an installed WSL distribution. Native POSIX
fixture launch and process-group behavior require their own Kali checks;
Windows passes must not be presented as Kali results. Real provider binaries,
controlled source compatibility, and DNSx are also **not verified** by this
offline laboratory.

```sh
python3.12 -m unittest tests.test_benchmark_subdomain_data tests.test_benchmark_subdomain_provider tests.test_benchmark_subdomain tests.test_benchmark -v
```

## Hylianlab Kali laboratory plan

The implemented offline integration battery is the first stage of the
broader laboratory. Run its exact oracles and cleanup checks in Kali before
claiming Kali acceptance or increasing beyond 100k. Larger workloads must be
explicit, bounded, and fit recorded VM resources; no automatic unbounded
scaling is implemented.

The remaining stages below are deferred. `.test` and its descendants are
reserved for special use in the
[IANA registry](https://www.iana.org/assignments/special-use-domain-names).
Creating local DNS records alone does not feed Subfinder's
[passive online sources](https://docs.projectdiscovery.io/opensource/subfinder/overview).
Provider discovery data and DNS responses therefore require separate controls.

### Real-provider compatibility battery — not verified

Pin installed Subfinder/Amass versions and record actual help, commands,
binary/config hashes, source selection, credential availability without secret
values, limits and ordering. Use fresh Amass storage per sample. Verify passive
configuration and graph extraction for those actual binaries; the simulated
engine/graph does not establish their compatibility or online coverage.

First prove one controlled local source per real provider. Inspect official
source code and actual help for endpoint/proxy/config support, then validate
request/response contracts against a local service. A resolver override alone
is insufficient. Subfinder's documented
[source/configuration/proxy controls](https://docs.projectdiscovery.io/opensource/subfinder/usage)
do not prove arbitrary endpoint support for every source. Record source
patches, custom builds or TLS adaptations as adapted-provider tests. Local
source feasibility remains not verified until that experiment succeeds.

Then compare each provider directly versus integrated, and both providers
directly versus integrated. Joint execution is sequential Subfinder then
Amass in both flows; declare equivalent merge/saving and graph-retrieval
boundaries. Keep laboratory networking confined and public forwarding denied.
Public-source runs require a separate explicit selection and authorized real
targets, and cannot use the fictional dataset as a known discovery oracle.
External variability can make timing differences descriptive rather than
attributable to Hylianscan.

### Separate DNSx battery — not implemented or verified

Reuse the candidate manifest with an independent expected DNS-response map.
Start with a local authoritative CoreDNS zone using its
[file plugin](https://coredns.io/plugins/file/); the
[template plugin](https://coredns.io/plugins/template/) can define error
responses. Validate server/fault behavior before treating it as an oracle.

Cover A/AAAA/dual-stack, CNAME chains, NXDOMAIN, NOERROR without addresses,
SERVFAIL, delays/timeouts, retry limits, and wildcards. Keep discovered
candidates separate from names with confirmed address records. Compare
wildcard filtering enabled/disabled; resolution alone does not establish
passive discovery or an explicitly configured name.

Use explicit local resolvers and fixed concurrency/rates/retries, record
query/response logs and caches, and block public forwarding. Check flags
against the pinned binary and
[official DNSx usage](https://docs.projectdiscovery.io/opensource/dnsx/usage).
DNSx remains a separate measurement stage; HTTPx, websites and active TCP
scanning remain outside these batteries.
