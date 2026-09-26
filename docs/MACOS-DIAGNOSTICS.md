# Mac health diagnostics

Run the installed client's `--diagnostics` mode as administrator, or invoke
`/bin/sh '/Library/Application Support/AegisAgent/mdm-macos-compliance.sh'`
from MDM. The wrapper checks the installed path's owner and write permissions,
runs the embedded diagnostics capability check, then delegates to the client.
No external Python, package manager, network request or scan is required.
`--diagnostics-selftest` is unprivileged and does not inspect installation data.
Both modes reject additional arguments.

The output is one `aegis.macos-health/v1` JSON object. It contains no host/user
identity, device serial, collector address, credentials, paths or finding text.
Files are opened read-only with bounded sizes; symlinks, hardlinks, nonregular
files, unexpected ownership and unsafe permissions are rejected. Credentials and
upload receipts require private permissions. Diagnostics never repairs state.

Reporting configuration uses the same descriptor-based reader and validation as
the Mac scanner and native writer. Extended ACLs on its file or directory,
duplicate JSON fields, concurrent file mutation, invalid UTF-8 and input over
32 KiB are refused. A rejected configuration also leaves reporting health false,
even if an old successful upload receipt exists. Other diagnostic files retain
their existing bounded readers; this is not a claim of ACL validation for every
file in the installation.

| Field | Meaning |
| --- | --- |
| `AegisInstalled` | A nonempty canonical client could be read safely; not an authenticity claim |
| `AegisIntegrityValid` | Client and packaged baseline match the local package inventory, or a matching local update receipt for the new client version |
| `AegisIntegrityScope` | Always `local-package-checksums`; these checks do not authenticate the publisher or protect against a privileged attacker replacing both files and inventory |
| `AegisLaunchDaemonRegistered` | `system/com.aegis.agent` is registered with launchd |
| `AegisLaunchDaemonHealthy` | launchd reports the canonical program running with a live PID, no registered legacy system service, and no pending watch cleanup marker; not proof that enforcement is effective |
| `AegisLegacyServicePresent` | The old `com.company.aegis-agent` system service is still registered and needs migration |
| `AegisReportingConfigured` | A private, structurally valid HTTPS reporting configuration exists; does not prove credentials are accepted |
| `AegisReportingHealthy` | Local accepted-upload receipt matches that collector and the exact current URL/credentials fingerprint, and is less than two hours old; does not perform a new server check |
| `AegisPolicyVersion` | Valid active policy version; no hardcoded old release or factory-policy hash comparison |
| `AegisReportValid` | Report schema, client/policy versions and recomputed severity counts are consistent |
| `AegisScanRecent` | Valid report timestamp is less than two hours old and not in the future |
| `AegisFindingsKnown` | Counts come from a valid report, which can still be stale; always check `AegisScanRecent` too |
| `AegisCriticalFindings`, `AegisHighFindings` | Counts only; zero with `AegisFindingsKnown=false` means unknown, not clean |
| `AegisDiagnosticIssues` | Fixed diagnostic codes; no raw exception strings or input content |

The package includes `aegis-runtime-manifest.json` for both architecture digests
and the packaged baseline. Mutable active policy is intentionally outside that
inventory. Successful frozen Mac updates write a private
`aegis-update-receipt.json` using the applied artifact digest already verified by
the updater. A missing/invalid receipt makes integrity unconfirmed after version
drift. Receipt-write failure is reported as `updated_receipt_unavailable`; the
client replacement has still occurred. Neither receipt nor inventory replaces
signed-update verification.

Diagnostics reads `last-report.json` and `upload-status.json` beside the installed
client, matching the system package's service arguments. Old user-level report
paths do not count as evidence for the system client. A valid summary exits 0
even when unhealthy; MDM must evaluate the fields. Missing runtime/capability
exits 1 with an all-false summary; nonadministrator or extra wrapper arguments
exit 2. The direct client refuses nonadministrator access with a structured
summary. A malformed direct CLI invocation exits 2 without reading state.

Source tests cover stale and malformed reports, counts, unsafe files, service
failures, legacy services, cleanup markers, drift receipts and wrapper boundaries.
Native ARM64/Intel CI runs the frozen diagnostics against root-owned synthetic
state with network/external Python execution denied. These tests do not install
on a real managed endpoint or establish full client compliance. See
[remaining lifecycle gates](MACOS-RUNTIME-CONTRACT.md).

Credential rotation and URL-path changes require a new accepted upload before
reporting becomes healthy. Older receipts without a configuration fingerprint
are unconfirmed until that upload. See [configuration operations](MACOS-CONFIGURATION.md).
