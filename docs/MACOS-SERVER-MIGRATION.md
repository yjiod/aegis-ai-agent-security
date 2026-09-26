# Mac runtime server migration

The system client's scan cycle now uses the embedded enrollment validator and
protected reporting writer for a server change. It does not need external
Python. A migration changes reporting credentials only; existing policy, baseline
and signing trust anchors stay intact. Do not interpret migration as successful
policy adoption or accepted reporting by the new server.

Administrators can deliver `server-override.json` beside the system client through
a managed file deployment. It must be a root-owned private regular file (0600),
without additional hardlinks, symbolic links or extended ACLs. Its parent must
also pass the protected directory checks. Example using a synthetic address:

```json
{"server_url":"https://new.example.test"}
```

The single legacy field `server` is also recognized. Additional fields, duplicate
JSON keys, malformed or oversized input are refused. The URL must be ASCII HTTPS
without user information, query, fragment or invalid port. A bare origin or one
of the established enrollment/report/policy/manifest endpoint paths is accepted;
other paths are refused rather than silently truncated. Deploy the file
atomically; a partial write is invalid and will not initiate enrollment.

If a device enrollment file or directory is selected, this migration is refused.
That includes invalid device credentials: the override must never erase the
error and downgrade to common reporting configuration. Those devices need a
separate migration of their device credential contract. Custom reporting-file
destinations are also refused; this path owns only the system `reporting.json`.

An exact full report URL match avoids repeated enrollment. Matching the host
alone is insufficient. For a changed URL, the client validates the new response
using the same bounded HTTPS rules as [system enrollment](MACOS-ENROLLMENT.md).
Where required, the deployment must supply the destination's enrollment key via
protected service environment configuration, not this JSON file. The running
service retains that environment value for subsequent attempts; it never prints
it or places it in an argument.

Before commit, the client rereads the protected migration request and checks it
has not changed. The reporting writer compares the state captured before the
network request under its private write lock. A changed request or intervening
configuration edit causes refusal. These are protected snapshots, not a lock
shared with arbitrary administrator tools or a transaction across both files.
A change after the final request check can be observed on the next scan cycle.

Pre-commit failure keeps the old local configuration and runtime report target.
A successful commit selects the new credentials for the current scan. If the
parent-directory sync fails after replacement, the client uses the new config
and emits `server_migration_durability_unconfirmed`; it must not claim the old
config was retained. Health remains unconfirmed until the new server accepts an
upload matching the current configuration. A failed attempt produces a fixed
migration finding without response content or credentials. Retries follow scan
cycles; the enrollment socket timeout is not a total operation deadline.

Remote credential issuance may already have occurred before a local failure.
This path does not roll it back, revoke the old server's registration or move
queued reports. Idempotent server issuance, queue treatment, trust-anchor change,
per-device migration and end-to-end acceptance remain required deployment work.
The historical user-level install script also remains separate and still blocks
full [R7 acceptance](MACOS-RUNTIME-CONTRACT.md).

Tests exercise synthetic transport, real protected files, native ACL refusal,
concurrent edits, policy/key preservation, same-host path changes, device-mode
refusal and applied-but-unconfirmed durability. Native CI runs these as both the
normal test user and system owner. The frozen self-test includes the migration
parser. This does not prove a live cross-server migration on a signed endpoint.
