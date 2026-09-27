# Subfinder 2.14.0 compatibility result

The official Windows amd64 v2.14.0 release passed Hylianscan's real-binary
compatibility check on 2026-09-27. The release archive's SHA-256 was
`84e8a01d3d062484bb0958445e635a5773b6671566407fb4ab48417391539681`,
matching the GitHub release API digest. See the [official release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.14.0).

The binary reported v2.14.0 and exposed `-d` and `-silent`. The reserved
`example.test` check completed with nine scoped names; the `.invalid` check
completed empty; an unknown option exited with status 2. A Hylianscan CLI run
saved the same nine names in TXT and JSON, with provider status `completed`.
The focused offline suite passed: 61 tests, one skipped. The full local suite
passed: 390 tests, one skipped.

This version was manually added to `tested_versions` after the Windows check.
Linux real-binary coverage is pending; the scheduled compatibility workflow now
includes every tested version on Ubuntu and Windows.
