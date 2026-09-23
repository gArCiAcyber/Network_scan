# Subfinder 2.13.0 compatibility result

This audit compares the official Windows amd64 Subfinder 2.13.0 release with
the Hylianscan baseline, 2.16.0. The binaries were downloaded from the official
GitHub release assets using `scripts/provider_updates.py install`; the installer
verified each GitHub API SHA-256 digest before extraction.

## Evidence

The captured fixture is [subfinder_real_output.json](../tests/fixtures/subfinder_real_output.json).
It records the exact command arguments, version output, relevant help flags,
unknown-flag behavior, empty output, timing, and release provenance. The binary
paths used during this run were:

```text
E:/hylianscan-compatibility/subfinder/2.13.0/subfinder.exe
E:/hylianscan-compatibility/subfinder/2.16.0/subfinder.exe
```

The downloaded archive SHA-256 digests were `4749e3701970d072f2f5405ae85339cf0be8bd15ad7642b239b16f3f50635fbf`
for 2.13.0 and `ef760f0a064c22811100c75a61da35ba73d71398cb99ae85d32d0eed44496ab8`
for 2.16.0, matching the GitHub release API metadata.

Both binaries reported their expected version on `-version`, returned the same
required integration flags (`-d`, `-silent`, `-version`, `-timeout`, and
`-max-time`) in help, and returned exit code 2 with the same text for an unknown
flag.

The bounded commands used reserved `example.test` data:

```text
subfinder.exe -d example.test -silent -timeout 1 -max-time 1
subfinder.exe -d example.test -silent -sources crtsh -timeout 1 -max-time 1
```

2.13.0 returned nine unique subdomains for the all-source command in 2.266
seconds. The captured lines are replayed through Hylianscan's real file-backed
provider parser and report writers; duplicate replay is deduplicated and saved
in sorted TXT and JSON results. The source-specific `crtsh` command returned
exit 0 with empty stdout for both versions (2.277 seconds for 2.13.0 and 2.25
seconds for 2.16.0).

2.16.0 did not produce output before the independent 8-second harness bound for
the all-source command. Its source-specific `crtsh` command completed empty in
2.25 seconds. Hylianscan's own runner also returned `timed_out` within its 5-
second budget when each binary was run against the reserved target. This is
execution evidence, not proof of an upstream regression: passive sources,
network conditions, local provider configuration, and API rate limits can change
the result.

## Decision

Subfinder 2.13.0 is now listed in `tested_versions`. Its official Windows amd64
binary reported the expected version, exposed the required flags, produced
in-scope output that Hylianscan parsed and deduplicated, and handled empty output
and invalid flags as expected. The committed replay test verifies parsing and
TXT/JSON reporting without network access.

This certifies the captured Windows integration contract; it does not guarantee
provider source availability or performance, and Linux real-binary coverage is
still pending. The registry entry is:

```json
"tested_versions": ["2.13.0", "2.16.0"]
```

## Platform coverage

Windows amd64 was tested locally with both official binaries. Ubuntu was not
available in this environment, and no GitHub Actions run was executed from this
audit; Linux coverage remains pending. The scheduled provider-compatibility
workflow can test the same fixture and release contract on Ubuntu and Windows.

## Tests

The new offline replay suite checks version/flag evidence, normal output parsing,
duplicate handling, empty output, timeout handling, and TXT/JSON serialization.
The full repository suite and compilation checks were also run. A successful
test replay does not turn 2.13.0 into a supported baseline; that requires
repeatable real-binary output evidence on both platforms or an explicit reviewed
policy decision.
