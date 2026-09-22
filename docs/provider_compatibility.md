# External provider compatibility

Hylianscan uses the packaged `modules/provider_compatibility.json` registry for
Subfinder, Amass, and DNSx. HTTPx and Nmap retain their existing integrations;
they have not been added to this version policy yet.

## Startup policy

1. Resolve every selected executable before starting any process.
2. Run each tool's registered version and help commands locally. Both commands
   share at most 10 seconds, deducted from that provider's process budget.
3. Warn on stderr for unreadable, ambiguous, prerelease, unknown-major, and
   otherwise unsupported versions, including in quiet mode, then continue when
   the required CLI options are present.
4. Stop before enumeration when the help command fails or a required CLI option
   is absent. A version listed in `tested_versions` is **tested**; another stable
   version in `supported_majors` is **untested** until CI evidence is reviewed.

Installed executables remain separately managed. Startup does not query GitHub
or update binaries. Existing execution-time checks and process cleanup remain in
place. Missing tools and required-option failures leave existing reports intact.
An unsupported provider can fail its own run without suppressing completed
evidence from other selected providers. JSON provider entries gain an optional `compatibility`
object containing `version`, `status`, and `executable`; existing fields retain
their meanings. The recorded version is the startup observation.

## Baselines and evidence scope

| Provider | Baseline | Supported majors | Real-binary checks |
| --- | --- | --- | --- |
| Subfinder | 2.16.0 | 2 | Version and required CLI options |
| Amass | 4.2.0 | 3, 4 | Version and passive enumeration CLI options |
| DNSx | 1.3.1 | 1 | Version/options; localhost A/AAAA, JSON, NXDOMAIN, empty input |

These are **integration contract baselines**, not guarantees that every remote
data source works. Subfinder/Amass output parsing, provider combinations, errors,
timeouts, cancellation, and partial evidence are covered by the offline suite
using controlled processes/fixtures. No public-domain enumeration is part of the
scheduled checks. Amass 3.x remains supported with an untested-version warning.
Amass 5.x versions retaining the registered legacy flags warn during startup,
then their provider run reports that the separate engine/session integration is
unsupported. A version missing those required flags fails startup.

## Release monitoring and review

`.github/workflows/provider-compatibility.yml` runs daily and can be dispatched
manually. Every run queries each registry repository's latest stable GitHub
release and tests both the baseline and latest version on Ubuntu amd64 and
Windows amd64, including unsupported latest releases. A manual dispatch can add
one historical provider/version pair, such as `subfinder` and `2.13.0`. API
failures fail detection without replacing the previous manifest.

The workflow runs the offline regression suite on both operating systems. It
uses only reserved domains, localhost, controlled fixtures, and captured output;
it never enumerates a real domain. Each real binary check records the exact
version, required options, exit behavior, and provider-specific controlled
checks. The offline suite covers normal and empty output, duplicates, errors,
timeouts, Hylianscan parsing, provider combinations, and TXT/JSON reporting.

The review job classifies each provider/version automatically:

- **approved**: all mandatory checks passed on both required amd64 platforms and
  the cross-platform regression suite passed.
- **limited**: evidence is missing, installation or timeout prevented a complete
  result, or the regression suite failed.
- **incompatible**: a mandatory version, option, output, or behavior check failed.

Approved stable versions inside an already supported major are proposed in
`tested_versions`. Unsupported majors are never added to `supported_majors`
automatically. The workflow preserves all available evidence and prepares one
reusable PR branch, `automation/provider-compatibility`, updating:

- `docs/provider_updates.json`: observed releases and current policy status.
- `docs/provider_update_checks.json`: actual regression/smoke outcomes and evidence.
- `modules/provider_compatibility.json`: reviewed promotion proposals for versions
  classified as approved.

Failed checks leave the workflow failed but still produce a review PR when
detection succeeds. Missing evidence is never a passing check. Registry changes
require merging the PR; the workflow never merges it. Repeated identical results
produce no new change. Live checks against explicitly authorized targets remain
manual or belong in a separate explicitly authorized workflow.

### Enable in GitHub

The workflow must be merged into the default branch for scheduled runs. GitHub
Actions must be enabled, and the repository setting allowing Actions to create
pull requests must be enabled. The review job requests `contents: write` and
`pull-requests: write`; other jobs have read-only permissions. Repository or
organization restrictions can prevent PR creation. PRs created with the default
`GITHUB_TOKEN` do not trigger ordinary PR workflows; this workflow supplies its
own test evidence before creating the PR. Dispatch validation again after changes.

### Promote a release

Review the official changelog and the generated evidence. An approved PR may add
an exact version to `tested_versions`; merge it after review. If arguments,
output formats, or process lifecycle changed, update the integration and a
focused captured fixture before rerunning the workflow. Changes to `baseline`,
capabilities, or `supported_majors` remain deliberate manual registry changes.

### Local maintenance commands

From the repository root, with Python 3.12:

```sh
python scripts/provider_updates.py monitor --output /path/to/provider-updates.json
python scripts/provider_updates.py monitor --provider subfinder --version 2.13.0 --output /path/to/provider-updates.json
python scripts/provider_updates.py install subfinder 2.16.0 --destination /path/to/isolated-tools
python scripts/check_provider.py subfinder 2.16.0 --executable /path/to/isolated-tools/subfinder --output /path/to/check.json
python -m unittest discover -s tests -p "test_*.py" -v
```

Use Windows paths and `.exe` where appropriate. The installer supports Linux and
Windows amd64 release archives, downloads from the registry's official GitHub
repository, verifies the API's SHA-256 digest when provided, and extracts only
the executable into the explicitly chosen directory. Older releases without an
API digest rely on HTTPS delivery from that repository. It never changes PATH or
system-managed installations. Network requests have timeouts; CI jobs also have
an overall time limit.

## Adding another tool

Add its official repository, tested baseline, supported majors, version/help
arguments, and required flags to the registry. Wire the existing preflight into
the integration and add parser/lifecycle fixtures plus a controlled real-binary
check in `scripts/check_provider.py`. The monitor automatically discovers registry
entries. Tools with different release naming or distribution formats also need
an explicit installer adjustment; adding metadata alone does not implement an
integration.
