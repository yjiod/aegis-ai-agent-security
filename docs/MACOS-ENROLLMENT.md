# Mac system enrollment

The system package invokes the installed, self-contained client's exclusive
`--install-config` mode as root. This mode uses embedded libraries and never
starts or downloads an external Python interpreter. The approved HTTPS server
address comes from the package build. The installer no longer interprets the
legacy global server override file or parses credentials with shell expressions.

Existing `reporting.json` must pass the protected reader's ownership, permission,
ACL, regular-file, schema, URL and independent credential checks. An exact match
of its full report URL preserves the file without contacting enrollment. A
different server or URL path returns `server_migration_required`; installation
does not silently transfer the endpoint. Format-valid credentials can still be
revoked remotely: preservation does not prove accepted reports.

A missing configuration or format-invalid but filesystem-protected file can be
repaired by enrollment. Unsafe filesystem state is refused before the request.
The request contains only the pseudonymous device identifier and agent version.
If the deployment requires `AEGIS_ENROLLMENT_SECRET`, supply it through protected
deployment environment injection, never arguments, scripts or logs. The native
mode consumes and removes it. Environment transport does not protect against
privileged observers. Legacy manual token arguments are refused; provisioning
two explicit credentials uses [protected configuration](MACOS-CONFIGURATION.md).

Enrollment and reporting must use the same HTTPS origin with certificate
verification enabled. Redirects are refused. Responses must have status 200,
the requested final URL, JSON media type and identity encoding, with a body no
larger than 4 MiB. Duplicate JSON fields, malformed UTF-8, excessive nesting,
invalid or conflicting lengths, incomplete responses, wrong schema/device/report
URL and missing, short or equal credentials are refused. The socket I/O timeout
is 25 seconds; it is not a hard end-to-end wall-clock deadline.

Validated responses are committed through the private locked configuration
writer. It compares the file state captured before networking with the state
under the lock, refusing to overwrite intervening local changes. Pre-commit
failure preserves local bytes. This is not a distributed transaction: the server
may already have issued or changed credentials before a local failure. Server
issuance rollback and idempotent recovery still require separate work.

Only reporting credentials are written. Optional policy and trust-key fields
in the enrollment response are ignored; they do not replace active policy or
establish a signing trust anchor. The factory or existing policy remains in use.
Initial trusted policy provisioning and subsequent signed policy delivery must
be verified separately. Credentials are not copied into the old Swift prototype's
configuration; that prototype and the system service are not yet a unified UI.

The fixed `aegis.enrollment-result/v1` result never includes credentials, response
content or endpoint identity. `configured_health_pending` and
`preserved_health_pending` exit zero. Every result has `health_verified=false`.
`applied_durability_unconfirmed` exits nonzero with `applied=true` if replacement
occurred but parent-directory syncing failed. Other failures exit nonzero with
`applied=false`. The package retains its pending marker after a failure and may
register the service, so Installer success alone must not be recorded as an
enrollment or health success. Confirm accepted uploads using native diagnostics.

Source tests use synthetic transport and files. ARM64 and Intel CI exercise the
frozen mode with root-owned synthetic state, external executables and networking
denied, covering preservation and offline failure. Package tests use isolated
service fixtures. These checks do not prove live server enrollment, signed
distribution or the complete no-Python lifecycle on a clean endpoint.

Runtime server overrides now use [protected migration](MACOS-SERVER-MIGRATION.md).
Legacy user enrollment, automatic network repair,
policy trust bootstrap, UI integration and installer recovery remain separate
work under [R7](MACOS-RUNTIME-CONTRACT.md). Do not describe those paths as migrated
or automatically repaired by this change.
