# macOS package lifecycle validation

The system package installs `com.aegis.agent`. Its payload contains
`aegis-policy.factory.json`; the mutable `aegis-policy.json` is initialized only
when absent. A same-console reinstall with existing enrollment preserves the
active policy and reporting configuration. Changing enrollment can still replace
the policy with the policy returned by the server.

Native packages require both ARM64 and x64 artifacts. The installation selects
the current architecture and requires its self-test to succeed. Script packages
include the self-update module and select a Python interpreter that passes the
packaged agent's self-test; that exact interpreter is written to the service
configuration. Script packages still require an available Python installation.

A successful installation script means launchd accepted the service and the
service registration could be read back. It does **not** establish daemon health,
successful enrollment or an accepted report. Offline enrollment remains marked
`enroll-pending`. Failed registration now returns a nonzero installation result;
payload changes are not automatically rolled back.

On macOS, run:

```sh
python3 -m unittest discover -s tests -p test_macos_package.py -v
```

These tests build and expand actual `.pkg` files, verify packaged Python source
and self-test execution, overlay the payload onto existing synthetic state, and
execute the extracted installation script in a temporary directory. Hardware,
enrollment, ownership and launchd operations use fixtures. The architecture
selection test uses distinct shell fixtures, not native machine-code binaries.
No production configuration or managed user baseline is read or modified.

This evidence does not cover a privileged Installer run, a real daemon restart,
Intel hardware execution, signing/notarization, trusted update rollback,
enforcement recovery or uninstall. Those remain separate release gates. The
user-level `.run` installer and Swift menu application also need separate
integration validation; this change covers the system `.pkg` only.
