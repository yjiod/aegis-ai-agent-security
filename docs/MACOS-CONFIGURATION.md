# Mac reporting configuration

The system package includes `aegis-configure-macos.sh`. It invokes the embedded
client's exclusive `--configure-reporting` mode, after an unprivileged capability
self-test. It does not invoke external Python or download a runtime. Run as root
through the managed deployment mechanism:

```sh
/bin/sh '/Library/Application Support/AegisAgent/aegis-configure-macos.sh'
```

Supply `AEGIS_REPORT_URL`, `AEGIS_REPORT_TOKEN` and
`AEGIS_REPORT_SIGNING_SECRET` through protected MDM environment variables or a
local secrets broker. Do not put actual values in scripts, command arguments,
shell history, logs or tickets. Environment transport is not protection against
a privileged observer. The client consumes and removes the credential variables
from its environment; it never prints their values. No network operation is
performed by this configuration command.

The URL must be an ASCII HTTPS URL without user information, query, fragment,
whitespace or invalid port. Encode non-ASCII URL components before provisioning.
The two independent credentials must each contain 32–4096 printable ASCII
characters without whitespace. Inputs are validated before opening writable
state. Nothing invents a replacement signing secret when input is missing.

Only `reporting.json` beside the installed client is written. The system wrapper
locates that client under `/Library/Application Support/AegisAgent`; an existing
`AEGIS_REPORT_CONFIG` override is accepted only if it exactly names that file.
Custom output destinations are rejected. Missing installations must be repaired
with the system package first.

Writes use directory-relative descriptors, refuse symbolic links, hardlinks,
nonregular files, unsafe ownership/permissions and extended ACLs. The Mac ACL
check uses [Apple's descriptor ACL API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get.3.html);
tests exercise real ACL-bearing synthetic files/directories. ACLs are not silently
removed or reinterpreted. The existing install directory must be administrator
owned and not writable by group/others; configuration and lock files must be
private. Existing malformed JSON can be replaced if its filesystem protections
are valid; the old credential content is not read.

A private lock serializes this entry point. The writer syncs a private temporary
file, checks that existing state has not changed, atomically replaces the config,
then syncs its parent directory. Validation, lock contention, file sync or replace
failure preserves the existing config and removes the temporary file. A crash
can leave a private temporary file; it is never promoted automatically. Other
legacy writers do not yet honor this lock, so it does not guarantee serialization
against every old enrollment/installer path. Policy, baseline, UI configuration,
services and enrollment identity are not modified by this command.

The native system-package enrollment now uses this writer with an expected
pre-request file state. A concurrent configuration change while enrollment is
in flight is refused under the lock. See [system enrollment](MACOS-ENROLLMENT.md)
for its response validation and remaining legacy-path boundaries. Runtime Mac
server migration uses the same writer and expected-state check; its administrator
intent uses the shared bounded private JSON reader before schema validation.

Output is a fixed `aegis.configuration-result/v1` object with operation, applied
boolean and status, suitable for the MDM operation log. `applied` exits 0.
`applied_durability_unconfirmed` exits 1 with `applied=true`: replacement occurred,
but the directory sync failed; do not report that the old config was retained.
Other failures exit nonzero with `applied=false`. The wrapper returns 2 for a
nonadministrator or extra arguments and 1 for unavailable/untrusted runtime.

The next scan reads the new configuration. A successful upload records a private
HMAC fingerprint bound to the exact URL, token and signing secret actually used.
Diagnostics requires that fingerprint to match the current configuration. A
different token, secret or URL path invalidates the old success evidence even if
the collector hostname is unchanged. Older receipts without fingerprints remain
unconfirmed until the new client successfully uploads. The fingerprint never
appears in the public health summary and is not a publisher-authentication proof.

On macOS the scanner and health diagnostics share a protected configuration
reader with the writer's schema, URL and credential validation. Each read opens
directory components and the final file without following links, checks owner,
permissions, single-link regular-file status and extended ACLs on descriptors,
then reads at most 32 KiB. This accommodates maximum credentials even when JSON
escaping expands them. Duplicate fields, non-UTF-8 input, excessive nesting and
oversized input produce fixed errors. Permissions/ACLs and file size/timestamps
are checked again after reading; concurrent mutation or replacement can cause a
refused read and must not count as accepted configuration. Reads do not acquire
the write lock or modify credentials, and do not guarantee the pathname stays
unchanged after a validated snapshot is returned.

The directory must be owned by the caller (root for the system service), not
writable by group/others and free of extended ACLs. Ancestor links are refused;
custom paths must identify a protected physical directory. Previously readable
but broadly accessible configuration can now be refused. Provision through the
native writer and verify new accepted uploads before rollout. Linux's legacy
reader, per-device enrollment files and old installer/enrollment writers remain
outside this change and require separate consistency work.

Native ARM64/Intel CI exercises the frozen configuration mode against synthetic,
root-owned installations with other executables and network denied. This is not
the full no-Python endpoint lifecycle acceptance. The [MDM bootstrap](MACOS-MDM-INSTALL.md)
now uses system package trust gates; legacy service migration, live enrollment
acceptance, rollback and signed distribution acceptance remain separate work in
[R7](MACOS-RUNTIME-CONTRACT.md).
