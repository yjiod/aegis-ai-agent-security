# Mac approved-package rollback and repair

`rollback-aegis-macos.sh` redeploys an explicitly approved native system package.
It is generated from the MDM bootstrap with a fixed rollback operation; release
verification rejects drift. It does not restore Python files, execute the damaged
current client, guess a previous version or trust an unverified local backup.

The administrator supplies the desired release from approved records. It may be
an earlier compatible release or the same version for repair. The endpoint does
not infer chronological version order or independently establish that the chosen
release was previously installed. Target selection, policy compatibility and
rollout serialization remain the deployment controller's responsibility.

Run the reviewed script as administrator with public artifact identity only:

```sh
sudo /bin/sh ./rollback-aegis-macos.sh \
  -PkgPath "$APPROVED_RECOVERY_PACKAGE" \
  -PkgSha256 "$APPROVED_RECOVERY_PACKAGE_SHA256" \
  -TeamId "$APPROVED_PUBLISHER_TEAM_ID" \
  -CurrentSha256 "$EXPECTED_CURRENT_RUNTIME_SHA256" \
  -TargetVersion "$APPROVED_TARGET_VERSION"
```

Use `-PkgUrl` instead of `-PkgPath` for an explicit HTTPS source. Rollback never
falls back to a download root or latest-package default. Package digest and
publisher identity must come from trusted release records, not the unverified
download server. MDM may set `AEGIS_MACOS_ROLLBACK_CURRENT_SHA256` and
`AEGIS_MACOS_ROLLBACK_TARGET_VERSION` along with the existing protected package
identity variables. Ordinary installation entries reject rollback parameters.

The expected current digest pins the canonical `aegis-agent` bytes at the fixed
system installation path; it is not the installed package's digest. The current
program can be unlaunchable. If a failed installation removed it, explicitly use
`-CurrentSha256 absent`; all parent directories must still be protected and the
path must be absent, including no dangling symlink. Existing files cannot satisfy
an absence precondition. A missing entire installation uses the normal trusted
installation path instead. Do not infer absence from an offline endpoint.

The entry checks current state before downloading and again immediately before
Installer. Root ownership, no group/other write bits, no ACL entries, no links,
single-link regular runtime and a bounded size are required. It does not execute
or read credentials from that installation. Legacy system services, legacy user
launch files and unconfirmed cleanup remain refusal conditions. Rollback cannot
be combined with user-service migration.

The target must pass the same full package digest, approved Developer ID Installer
publisher, enabled notarization assessment and no-override requirements as normal
installation. After these checks, system pkgutil expands metadata/scripts only.
The package must declare the existing native migration contract plus
`package_recovery=native-reinstall-v1` and the requested `agent_version`; the
declaration binds its postinstall digest. Bounded regular `PackageInfo` metadata
must name `com.aegis.agent`, match the target version and install at `/`. DTD/entity
declarations are refused and XML parsing prohibits network access. No expanded
script is executed during inspection. A declaration from the approved publisher
is a contract, not standalone runtime evidence; final package CI remains required.
Older packages without the recovery contract are refused and need a separately
built, approved and verified recovery package; do not bypass validation.

Installer success returns `rollback_installed_health_pending`, exit 0, operation
`rollback` and the requested target version. This means Installer completed, not
that the endpoint recovered. Confirm canonical runtime/version, launchd state,
protected reporting configuration, policy compatibility and accepted Collector
reports for that version before accepting recovery. The target version in the
bootstrap result is requested/validated package metadata, not a post-install
runtime observation.

The approved package's native enrollment preserves valid protected reporting
configuration only when its full report URL matches. Changing servers requires
the separate migration workflow. Reporting failures may leave pending enrollment;
package installation is not credential revocation or server transaction rollback.

This operation does not restore policy/baseline state at an earlier point in time,
undo enforcement actions or offline queue changes, or provide automatic Installer
transaction rollback. Installer can modify part of the system and then fail.
`installer_failed_state_requires_verification` must retain that uncertainty; inspect
state before retrying. Current-state checks are point-in-time checks, not a lock
against concurrent administrators or deployments. Do not dispatch overlapping
updates/repairs to the same endpoint. Full snapshot/transaction recovery and
deployment-controller coordination remain outstanding.

Tests use synthetic damaged runtimes and isolated signature/assessment/Installer
fixtures, plus actual pkgbuild/pkgutil metadata. They cover changed current bytes,
absence versus links, metadata/version/contract mismatch, wrong publisher and
Installer failure without touching live user data or services. They do not prove
signed production recovery or full [R7](MACOS-RUNTIME-CONTRACT.md) acceptance.
