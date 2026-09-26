# Retire a legacy Mac user service

The embedded `--retire-legacy-user` mode retires the invoking user's recognized
legacy LaunchAgents. It is not system uninstall or complete endpoint retirement.
It does not stop system services, select another account, parse credential
contents, remove baseline blocks or restore blocked assets.

The system package includes `retire-aegis-user-macos.sh`; run it as the affected
user without sudo. The reviewed historical launcher delegates identically:

```sh
/bin/sh '/Library/Application Support/AegisAgent/retire-aegis-user-macos.sh' --uninstall
# Compatibility filename, when separately built and distributed:
/bin/sh aegis-agent-macos-standalone.run --uninstall
```

`scripts/build-macos-standalone.sh` now emits only this maintenance launcher. It
does not append source/native payloads or build a new installer. New installation,
including from a cached package, uses the trusted system `.pkg` path described in
[MACOS-INSTALL.md](../public/downloads/MACOS-INSTALL.md). Already downloaded older
`.run` files are not retroactively changed; replace them through the approved
distribution process.

The launcher requires the native client already present at the fixed system
installation path. It rejects linked paths, non-root ownership, writable mode
bits, ACL entries and extra binary hardlinks, then checks the specific embedded
retirement capability. Missing/old runtime fails before service changes, with no
Python fallback. This ownership check relies on a previously trusted installation;
it is not independent publisher attestation. An endpoint with only the old Python
runtime still needs an approved native maintenance installation. A separately
signed standalone recovery tool remains outstanding.

The CLI rejects root and differing real/effective users. It takes no home, uid,
label or path argument. The account database supplies the current user's physical
direct child home under `/Users`; `HOME` and `SUDO_USER` cannot select the target.
Custom historical `AEGIS_INSTALL_DIR`, `AEGIS_PLIST` or `AEGIS_LABEL` settings are
refused by the launcher. Do not remove such settings and assume a different scope
is equivalent.

Before stopping services, the module verifies all recognized launch files and
the writable archive directories. Links, extra hardlinks, unsafe ownership/mode,
ACLs and nonregular files refuse retirement. It takes a private nonblocking lock
and writes a partial journal before any stop. Only `com.aegis.agent` and
`com.company.aegis-agent` in the current uid's `gui` and `user` domains are stopped.
Missing launch files do not imply jobs are absent; missing/unknown domains and
job results follow the shared launchd verification contract.

Launch files are moved with Darwin's exclusive no-replace rename into a random
private batch under `~/Library/Application Support/AegisLegacyRetirement/`.
Each move checks the original file metadata, syncs both directories and records
a checkpoint. The final check refuses recreated launch files, reappeared or
unconfirmed service registrations, and pending scan cleanup. Runtime contents,
credentials, user baselines and other accounts remain in place. Journals contain
fixed launch names and file metadata, without home paths or file contents.

The fixed public result has schema `aegis.user-retirement-result/v1`, scope
`current_user`, retained-data flags and `health_verified=false`. Exit 0 with
`retired_with_retained_state` means the checked jobs were absent and identified
launch files were archived at the verification point. This does not prove detached
child processes exited, prevent future re-registration or revoke server identity.
Exit 1 is incomplete, possibly after some stops or moves. Exit 2 means unsupported
invocation/privilege. Never turn partial state into success merely because the
active plist is gone.

Failed batches remain for review. A move can succeed before its checkpoint is
durable, so compare retained files and recorded metadata before recovery. No
automatic restoration or service activation is performed. Re-running rechecks
current jobs/files and creates another batch; it does not erase or certify prior
partial batches. Do not blindly bootstrap archived files, overwrite active
configuration or restore an old user scanner alongside an active system scanner.
Complete retirement, credential revocation and recovery still require their
separate product workflows.

Source tests use synthetic homes and launchd fixtures, with real Darwin rename,
permission and ACL checks. Frozen tests deny real user-home reads, networking and
external executables, proving capability/argument rejection and safe failure.
They do not prove live user retirement or the full clean no-Python lifecycle.
