# Scanner watch shutdown

The Python watch runtime handles TERM and INT before spawning a scan. A stop
request terminates the scanner's owned process group, escalates to KILL when
needed and waits within bounded deadlines. Idle waiting uses a local signal
wakeup socket rather than polling throughout the scan interval.

POSIX child exits are observed without reaping. The original leader PID remains
reserved until the last group signal, avoiding a signal sent to a reused process
group ID. Once reaped, only signal-zero observations are used to confirm the group
has disappeared. The macOS system Python fallback uses Darwin's waitid ABI because
older system Python versions do not expose os.waitid.

A normally exiting scanner cannot leave descendants running in its original
group. Failed child exits are reported as scan failures. Failure to confirm
cleanup stops the watch loop and writes `watch-cleanup-pending.json` in the
runtime directory. Subsequent watch starts and the macOS uninstaller refuse to
proceed while that marker exists. Failure to persist the marker is reported;
durable fencing requires a writable runtime directory and functioning storage.

Validation uses owned synthetic child/grandchild processes, including TERM
ignoring descendants, early leader exit, scan timeout, idle shutdown, loss of wait
ownership and unresponsive-process simulation. An isolated launchd job runs the
actual watch loop and confirms its scanner group exits on bootout. These tests
never scan real user files or run an installed production Aegis service.

This is POSIX process-group supervision, not arbitrary process-tree containment.
Descendants that deliberately create a separate session, a hard-killed supervisor
that cannot run its handler, and uninterruptible kernel I/O remain limitations.
The Windows Python fallback controls its direct child; the Windows PowerShell and
.NET clients require their own lifecycle validation. Native binaries must be
rebuilt and signed before this source change can be called a native release.
