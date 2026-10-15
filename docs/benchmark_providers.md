# Controlled real-provider and DNSx acceptance

The accepted 2026-10-07 procedures are maintained in
`benchmarks/providers.py` and dispatched by `python -m benchmarks`.
Run as the ordinary Kali user. The launcher creates a unique evidence directory
and uses `unshare --user --map-root-user --net --mount --fork`; the worker rejects
the original network/mount namespaces, extra interfaces and routes. Only
loopback exists. Resolver mounts, public-looking loopback aliases and temporary
certificate trust apply only inside that owned namespace. No public forwarding,
provider patching, global trust change or host service shutdown is involved.

## Cases and selected executables

| Mode/profile | Cases | Required real tools |
| --- | --- | --- |
| `providers/quick` | Subfinder populated, successful empty source, CLI Subfinder | Subfinder 2.13.0 |
| `providers/full` | Quick plus empty owned Amass engine/session/graph, populated Amass, CLI Amass, combined DNSx, timeout and SIGINT partial persistence | Subfinder 2.13.0, Amass 5.0.0, DNSx 1.3.1 |
| `dnsx/quick` | Dual-stack/CNAME/negative/delayed/dropped queries, CLI completed and empty | DNSx 1.3.1 |
| `dnsx/full` | Quick plus IPv4, IPv6, wildcard distinction, timeout and SIGINT partial persistence | DNSx 1.3.1 |

The controlled lab pins these versions because its endpoint, resolver and graph
oracles were accepted with those actual binaries. Unknown versions stop this
lab; production compatibility warnings/continuation policy is unchanged.
Each selected executable gets the existing version/help compatibility checks.
DNSx is checked even for empty input; unselected real tools remain optional.
Python, Linux `ip`, `unshare`, and (for providers) `mount`/OpenSSL must be installed.

```sh
python3.12 scripts/benchmark.py --benchmark providers --profile full \
  --dnsx-path /path/to/dnsx --run-timeout 240 --resources
python3.12 scripts/benchmark.py --benchmark dnsx --profile full \
  --dnsx-path /path/to/dnsx --run-timeout 120 --resources
```

Source datasets and independent expected memberships live in the worker:
Subfinder returns four names; Amass graph extraction returns three, with one
overlap; six union candidates become five DNS-confirmed names. Fault cases
retain all six candidates and exactly two DNS findings, with exit 1/130 and
`timed_out`/`interrupted`. Amass's raw source entity without a graph relationship
is deliberately absent from its native `subs -names` oracle. This does not prove
complete CT coverage. DNSx-only cases use a committed discovery executable
fixture and real DNSx, including address families, CNAME, NXDOMAIN, NODATA,
SERVFAIL, dropped/delayed responses and wildcard-distinct addresses.

Evidence contains commands, pinned compatibility/binary hashes, namespace/
route information, source/DNS requests, per-case observations/oracles, actual
TXT/JSON, candidate checkpoints, accepted journals and owned PID/birth cleanup.
Amass graphs are retained; temporary private keys are removed. The default
disk reserve is 1 GiB. The launcher deadline includes the complete selected lab;
individual provider deadlines remain bounded. Stop only owned, matching births.

`--resources` measures the entire lab worker, including fixture services and
setup. Its CPU/RSS/descriptors are not pure provider cost. Timings are functional
observations, not calibrated rankings; reference/threshold options are rejected.
DNS/HTTP request logs show real workload traffic: a historical small-name Amass
campaign generated 9,713 DNS queries. Finding count is not a traffic budget.
Keep runs sequential and choose explicit time/disk/traffic budgets before any
future public-source campaign.

## Retained online source evaluation

The maintained full batteries passed in Kali on 2026-10-08 UTC: providers nine
of nine cases and DNSx eight of eight, including successful empty reports and
timeout/SIGINT persistence. The complete provider repetition closed the earlier
pending cleanup check: exited descendants awaiting the resource subreaper are
excluded using the existing live-process identity helper. An independent review
also found a cancellation race in the process checkpoint. Checkpoints now use
the existing atomic JSON writer, and launcher cleanup/key removal runs even
when reading that checkpoint fails. The 435-test suite and both full batteries
passed after this correction. Final guest checks found no remaining recorded
process births or temporary private keys. Permission failures during `/proc`
sampling preserve unknown process-tree peaks; waited-child CPU and `ru_maxrss`
remain separate. Raw commands, reports, logs and cleanup checks stayed outside
the repository.

```sh
python3.12 scripts/benchmark_source_health.py /path/to/passive.json \
  --source crtsh --output /path/to/new-evaluation.json
```

This reads retained evidence only. Existing output is never overwritten.
Process status/exit code, saved finding count, per-source health and exhaustive
coverage are separate fields. Recognized statistics with requests and zero
errors establish observed request health, including successful empty responses.
Positive errors report `request_errors`, regardless of finding count: failed
requests do not prove that every source route was unavailable. Missing/unknown
formats, zero requests or conflicting
warnings retain `unknown`. The `Errors` table header is never an error diagnostic.
Other providers without a recognized source-health format remain unknown.

The product JSON schema and checkpoints are unchanged. Reduced sanitized logs
from failed/successful samples and a successful-empty control are regression
fixtures. Preserved historical evidence is under `output/validation/` and is
intentionally not shipped in source control.

Official references: [Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage),
[DNSx usage](https://docs.projectdiscovery.io/opensource/dnsx/usage),
[Amass 5.0.0 resolver policy](https://github.com/owasp-amass/amass/blob/v5.0.0/engine/plugins/support/resolvers.go).
