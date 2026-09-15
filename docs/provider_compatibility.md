# External provider compatibility

Hylianscan uses the packaged `modules/provider_compatibility.json` registry for
Subfinder, Amass, and DNSx. HTTPx and Nmap retain their existing integrations;
they have not been added to this version policy yet.

## Startup policy

1. Resolve every selected executable before starting any process.
2. Run each tool's registered version and help commands locally. Both commands
   share at most 10 seconds, deducted from that provider's process budget.
3. Reject unreadable/ambiguous versions, prereleases, unknown major versions,
   failed/timed-out commands, and missing required CLI options before enumeration.
4. A version listed in `tested_versions` is reported as **tested**. Other stable
   versions in `supported_majors` are **untested**: warn on stderr, including in
   quiet mode, and continue only if the required CLI options are present. This
   allows updates within supported majors without claiming their output is verified.

Installed executables remain separately managed. Startup does not query GitHub
or update binaries. Existing execution-time checks and process cleanup remain in
place. Missing tools, unsupported versions, and failed startup checks leave
existing reports intact. JSON provider entries gain an optional `compatibility`
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
scheduled checks. Amass 3.x remains supported with an untested-version warning;
Amass 5.x remains blocked pending its engine/session integration.

## Release monitoring and review

`.github/workflows/provider-compatibility.yml` runs daily and can be dispatched
manually. It queries each registry repository's latest stable GitHub release,
then tests the baseline and any different latest version within a supported
major on Linux and Windows. Unsupported releases appear in the manifest but are
not installed or treated as successful compatibility checks. API failures fail
detection without replacing the previous manifest.

The workflow runs the offline regression suite on both operating systems and
saves real-binary results as artifacts. It prepares one reusable PR branch,
`automation/provider-compatibility`, updating only:

- `docs/provider_updates.json`: observed releases and current policy status.
- `docs/provider_update_checks.json`: actual regression/smoke outcomes and evidence.

Failed checks still produce a review PR when detection succeeds. Missing evidence
is not a passing check. The workflow never promotes a version into the runtime
registry or automatically merges a PR. Repeated identical results produce no new
change. Review the linked run logs for installation failures and artifact issues.

### Enable in GitHub

The workflow must be merged into the default branch for scheduled runs. GitHub
Actions must be enabled, and the repository setting allowing Actions to create
pull requests must be enabled. The review job requests `contents: write` and
`pull-requests: write`; other jobs have read-only permissions. Repository or
organization restrictions can prevent PR creation. PRs created with the default
`GITHUB_TOKEN` do not trigger ordinary PR workflows; this workflow supplies its
own test evidence before creating the PR. Dispatch validation again after changes.

### Promote a release

Review the official changelog and the evidence scope above. If command arguments,
output formats, or process lifecycle changed, update the affected provider and
add a focused regression fixture. Run the real-binary check and offline suite;
then deliberately update `baseline`, `tested_versions`, and capabilities in the
registry, with documentation in the same PR. Major versions require integration
review, not just adding their number to `supported_majors`.

### Local maintenance commands

From the repository root, with Python 3.12:

```sh
python scripts/provider_updates.py monitor --output /path/to/provider-updates.json
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
