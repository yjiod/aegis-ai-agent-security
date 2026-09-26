# Mac legacy user service preparation and recovery

The self-contained client provides three exclusive modes:

- `--service-migration-selftest`: no machine state changes.
- `--prepare-legacy-services`: root-only retirement of recognized user LaunchAgents.
- `--restore-legacy-services`: root-only restoration of recorded launch files;
  activation and reporting health still require verification.

No mode searches for or downloads Python. Preparation handles the two established
user service labels, `com.aegis.agent` and `com.company.aegis-agent`, in each
physical home under `/Users` (at most 64 homes). It does not migrate a legacy
system daemon. Credential files, personal baselines, quarantine and user runtime
contents are not read or changed. Launch plist contents are not read either.

Before stopping any service, the module validates all affected files and parent
directories without following links. It refuses additional hardlinks, nonregular
files, mismatched ownership, group/other writes and extended ACLs. Both existing
backups and cleanup-pending markers block unsafe preparation. A root-private
lock serializes these commands. The root-private journal lives beside the system
client as `legacy-service-migration.json`; home references are hashed and it
contains file metadata/checkpoints, never launch file content or credentials.

The durable `preparing` journal precedes service changes. Existing launchd domain
and service states are checked; bootout must succeed and registration must be
confirmed absent in both the GUI and user domains. Only then are launch files
renamed to `.plist.disabled-by-system-install`, using Darwin's exclusive rename
so an existing backup is never replaced. Each move is synced and checkpointed.
The result `prepared` means these launch configurations have been retired, not
that a new service is running or the endpoint is healthy. Repeating preparation
verifies the checkpoint and checks/removes any re-registered known services.

The package postinstall runs this capability from its validated native candidate
when legacy launch files or an existing migration journal are present, before
replacing the canonical executable or attempting enrollment. Failed preparation
stops postinstall; the old shell loop that ignored bootout/move failures is gone.
Installer has already laid down payload files at this point. This is not package
transaction rollback, and factory policy initialization may already have occurred.

After a failed attempt, inspect the fixed result and private journal through the
managed recovery process. Automatic preparation refuses incomplete journals.
Explicit `--restore-legacy-services` can restore checkpointed moves and leave
unchanged planned files in place, but only while the system Aegis service is
confirmed absent. Restoration never overwrites a newly created source, starts a
service, executes a plist or reads credential content. Success is deliberately
`restored_activation_pending`; verify the approved legacy configuration and
reactivate it through the managed service process before claiming recovery.

A crash or write failure between a rename and its checkpoint can leave an
ambiguous move. Modified/missing files, untracked backups, recreated launch files
or unconfirmed system-service state are refused. Preserve the evidence for
operator recovery; do not delete the journal or infer success from a filename.
Native health diagnostics treat incomplete, restored-but-not-activated or unreadable
migration journals as unhealthy; a journal does not replace live service/report
checks. A completed restore also requires explicit reconciliation before a new migration;
it is not silently treated as a fresh installation.

Registration removal does not prove every detached child process has exited.
Known watch cleanup markers block continuation, but complete process cleanup and
handoff to a healthy system client still require end-to-end validation. Source
fixtures exercise real Darwin rename/ACL behavior with synthetic launchd calls;
CI also tests root-owned fixtures and frozen refusal when home inventory is
sandbox-denied. They do not operate actual user services on a pilot endpoint.

The trusted MDM/interactive bootstrap now supports explicitly enabled user
migration after validating the signed package and its preparation contract;
legacy system daemons remain refused. Actual activation/recovery and end-to-end
handoff acceptance are outstanding. The historical enrollment filename now invokes the same trusted system-package bootstrap without external Python; old enrollment/uninstall settings are explicitly refused rather than reinterpreted. Standalone single-user retirement remains outstanding. This
increment is therefore not full legacy migration or [R7](MACOS-RUNTIME-CONTRACT.md)
acceptance, nor a signed production release.
