# macOS package lifecycle validation

The system `.pkg` requires both ARM64 and x64 Mach-O executables. Missing,
symlinked, script or mismatched-architecture inputs fail the build. The payload
contains the frozen clients, uninstaller, manual, factory policy and baseline;
it does not contain loose Python runtime modules. Launchd starts the canonical
`aegis-agent`, with no external interpreter selection or fallback.

The payload also includes a local runtime checksum inventory and the native-only
MDM compliance wrapper. Embedded [health diagnostics](MACOS-DIAGNOSTICS.md)
distinguishes file consistency, launchd state and recent accepted-upload evidence.
Local checksums do not authenticate the package publisher.

The installer verifies the selected native payload and runs both client and
embedded maintenance self-tests before overwriting the canonical client,
enrollment or service registration. Missing/broken maintenance leaves the
existing canonical client untouched. This does not imply full Installer rollback:
the payload and an initially absent policy may already have been written.

The Installer payload owns `aegis-policy.factory.json`, not the mutable active
policy. Same-console enrollment and existing policy are retained on reinstall.
Offline enrollment remains `enroll-pending`; confirmed launchd registration is
required for script success. Registration alone does not prove daemon health or
accepted reporting.

## Tests and native candidate packages

`test_macos_package.py` builds/expands real packages with small compiled ARM64/x64
fixtures. Each native runner executes its own architecture. The fixtures do not
scan or enroll; service and hardware operations are isolated doubles. They cover
invalid inputs, preservation, failed self-tests and service-registration failures.

`test_macos_frozen_package.py` takes explicitly supplied production-source frozen
artifacts through `AEGIS_MACOS_PACKAGE_BIN_DIR`. It builds and expands the package,
checks both payloads byte for byte and executes a relocated postinstall with
synthetic existing enrollment. Hardware/service commands are fixtures, network
access is denied, and a Python sentinel must not execute. The selected real client
then passes its embedded self-tests. No privileged Installer or actual managed
host service is invoked by this test.

The freeze workflow runs on native ARM64 and Intel x64. Its dependent packaging
jobs retrieve the artifacts from that exact workflow run, repeat the package test
on both architectures and retain unsigned candidate packages with a synthetic
server URL. These are review artifacts, not a signed distribution. The frontend
build no longer regenerates the retired user-level `.run`; new installs use the
system package. Mac builds without both native artifacts now fail deliberately.

## Update and uninstall

Mac binary update preflight requires successful `--selftest` and
`--maintenance-selftest` within one shared time budget. Old CLI formats, missing
maintenance, failure or timeout reject replacement and preserve the current
client and existing backup. Tests exercise the real update/apply function with
local synthetic manifests and also validate a real frozen candidate. Availability
checks do not authenticate an update or replace signature and provenance gates.

Maintenance modes reject mixed arguments before service or file access. The
uninstaller checks ownership/permissions, then invokes embedded maintenance;
there is no loose-helper or system-Python fallback. See the
[uninstall manual](../public/downloads/MACOS-UNINSTALL.md).

File cleanup tests and opt-in real isolated launchd tests remain separate from
frozen self-tests. `test_macos_native_maintenance.py` additionally exercises hostile
Python environment/module interference and a sandbox denying other executables,
network and external runtime locations, with a negative control proving denial.

## Remaining release gates

[R7](MACOS-RUNTIME-CONTRACT.md) still requires a complete lifecycle on clean
machines with no Python, Homebrew or developer tools. Tests on developer/CI hosts
and relocated scripts are narrower evidence. Final-package privileged install,
actual daemon/enforcement behavior, trusted update and rollback, complete uninstall,
MDM/online entry points, signing/notarization and final provenance remain unverified.
Mach-O format checks do not prove content identity or trusted origin. No package
should be accepted as a released client until all applicable gates pass.

Build dependencies and licenses are recorded in
[the freeze toolchain review](MACOS-FREEZE-DEPENDENCIES.md).
