"""Owned synthetic processes only: no endpoint scanning, enrollment or user data."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
AGENT=ROOT/"public/downloads/aegis_agent.py"
spec=importlib.util.spec_from_file_location("watch_agent",AGENT)
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

CHILD='''import os, signal, subprocess, sys, time
from pathlib import Path
root=Path(sys.argv[1]); role=sys.argv[2]; mode=sys.argv[3]
if mode == "ignore": signal.signal(signal.SIGTERM, signal.SIG_IGN)
if role == "child":
    subprocess.Popen([sys.executable, __file__, str(root), "leaf", mode])
(root / (role + ".pid")).write_text(str(os.getpid()))
if mode == "exit" and role == "child":
    deadline=time.monotonic()+5
    while not (root / "leaf.pid").exists() and time.monotonic()<deadline: time.sleep(.01)
    raise SystemExit(0)
# Fixtures have their own deadline even if the supervisor under test fails.
deadline=time.monotonic()+10
while time.monotonic()<deadline: time.sleep(.02)
'''

WORKER='''import importlib.util, json, sys
from pathlib import Path
root=Path(sys.argv[1]); config=json.loads((root / "config.json").read_text())
spec=importlib.util.spec_from_file_location("watch_agent", config["agent"])
agent=importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
argv=[sys.executable, str(root / "child.py"), str(root), "child", config["mode"]]
if config["mode"] == "short":
    argv=[sys.executable, "-c", "pass"]
    def idle(interval):
        (root / "idle").write_text("ready")
        return 3600
    agent.scan_sleep_seconds=idle
if config["operation"] == "watch":
    result=agent.run_watch_loop(argv, 30, 60, grace=.3, failure_marker=root / "cleanup.json")
else:
    result=agent.run_scan_cycle(argv, config["budget"], grace=1)
(root / "result.json").write_text(json.dumps(result))
'''


@unittest.skipUnless(os.name=="posix", "POSIX process-group lifecycle")
class WatchLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix="aegis-watch-lab-")
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name).resolve()
        (self.root/"child.py").write_text(CHILD)
        (self.root/"worker.py").write_text(WORKER)

    def configure(self,mode="normal",operation="watch",budget=30):
        (self.root/"config.json").write_text(json.dumps({"agent":str(AGENT),"mode":mode,"operation":operation,"budget":budget}))

    def wait_for(self,name,seconds=5):
        path=self.root/name
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if path.exists() and path.stat().st_size: return path
            time.sleep(.02)
        self.fail("fixture did not reach expected state: "+name)

    def assert_processes_gone(self):
        pids=[int(self.wait_for(name).read_text()) for name in ("child.pid","leaf.pid")]
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            live=[]
            for pid in pids:
                try: os.kill(pid,0)
                except ProcessLookupError: continue
                live.append(pid)
            if not live: return
            time.sleep(.05)
        self.fail("owned fixture processes survived cleanup")

    def worker(self,python=None):
        process=subprocess.Popen([python or sys.executable,str(self.root/"worker.py"),str(self.root)],
                                 start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def cleanup():
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)
        self.addCleanup(cleanup)
        return process

    def test_sigterm_cleans_child_and_grandchild(self):
        self.configure()
        process=self.worker()
        self.wait_for("leaf.pid")
        process.terminate()
        self.assertEqual(process.wait(timeout=5),0)
        self.assertEqual(json.loads(self.wait_for("result.json").read_text()),0)
        self.assert_processes_gone()

    def test_sigint_escalates_when_descendants_ignore_term(self):
        self.configure(mode="ignore")
        process=self.worker()
        self.wait_for("leaf.pid")
        process.send_signal(signal.SIGINT)
        self.assertEqual(process.wait(timeout=5),0)
        self.assertEqual(json.loads(self.wait_for("result.json").read_text()),0)
        self.assert_processes_gone()

    def test_completed_leader_does_not_leave_background_descendant(self):
        self.configure(mode="exit",operation="cycle")
        self.assertEqual(self.worker().wait(timeout=5),0)
        self.assertEqual(json.loads(self.wait_for("result.json").read_text()),"ok")
        self.assert_processes_gone()

    def test_timeout_cleans_ignoring_descendants(self):
        self.configure(mode="ignore",operation="cycle",budget=.8)
        self.assertEqual(self.worker().wait(timeout=5),0)
        self.assertEqual(json.loads(self.wait_for("result.json").read_text()),"scan_timeout")
        self.assert_processes_gone()

    def test_stop_before_spawn_and_failed_child(self):
        with patch.object(agent.subprocess,"Popen") as spawn:
            self.assertEqual(agent.run_scan_cycle(["unused"],1,stop_requested=lambda:True),"scan_stopped")
            spawn.assert_not_called()
        self.assertEqual(agent.run_scan_cycle([sys.executable,"-c","raise SystemExit(7)"],5),"scan_failed")

    def test_idle_stop_does_not_wait_for_next_scan_interval(self):
        self.configure(mode="short")
        process=self.worker()
        self.wait_for("idle")
        started=time.monotonic()
        process.terminate()
        self.assertEqual(process.wait(timeout=3),0)
        self.assertLess(time.monotonic()-started,2)

    def test_group_signals_precede_reaping(self):
        calls=[]
        class Child:
            pid=123
            def wait(self,timeout):
                calls.append("reap")
                return 0
        def send(process,force):
            calls.append("kill" if force else "term")
            return True
        with patch.object(agent,"_signal_scan",side_effect=send), patch.object(agent,"_await_scan_exit",return_value=True), patch.object(agent,"_await_scan_group_gone",return_value=True):
            self.assertEqual(agent._finish_scan(Child(),"scan_stopped",1),"scan_stopped")
        self.assertEqual(calls,["term","kill","reap"])

    def test_lost_wait_ownership_does_not_signal_a_reused_group(self):
        with patch.object(agent.subprocess,"Popen"), patch.object(agent,"_scan_exited",side_effect=ChildProcessError()), patch.object(agent,"_signal_scan") as send:
            self.assertEqual(agent.run_scan_cycle(["unused"],1),"scan_cleanup_unconfirmed")
            send.assert_not_called()

    def test_unconfirmed_cleanup_fences_restart_and_restores_handlers(self):
        marker=self.root/"cleanup.json"
        before={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
        with patch.object(agent,"run_scan_cycle",return_value="scan_cleanup_unconfirmed") as cycle:
            self.assertEqual(agent.run_watch_loop(["unused"],1,60,failure_marker=marker),1)
            self.assertEqual(cycle.call_count,1)
        self.assertEqual(marker.stat().st_mode & 0o777,0o600)
        self.assertEqual(json.loads(marker.read_text())["state"],"unconfirmed")
        with patch.object(agent,"run_scan_cycle") as cycle:
            self.assertEqual(agent.run_watch_loop(["unused"],1,60,failure_marker=marker),1)
            cycle.assert_not_called()
        self.assertEqual({sig:signal.getsignal(sig) for sig in before},before)

    def test_unresponsive_child_waits_are_bounded(self):
        class Child:
            pid=123
        with patch.object(agent,"_signal_scan",return_value=True), patch.object(agent,"_scan_exited",return_value=False):
            started=time.monotonic()
            self.assertEqual(agent._finish_scan(Child(),"scan_stopped",.02),"scan_cleanup_unconfirmed")
            self.assertLess(time.monotonic()-started,1)

    @unittest.skipUnless(sys.platform=="darwin", "system Python compatibility")
    def test_system_python_cleans_owned_group(self):
        self.configure(mode="ignore")
        process=self.worker("/usr/bin/python3")
        self.wait_for("leaf.pid")
        process.terminate()
        self.assertEqual(process.wait(timeout=5),0)
        self.assertEqual(json.loads(self.wait_for("result.json").read_text()),0)
        self.assert_processes_gone()

    @unittest.skipUnless(sys.platform=="darwin" and os.environ.get("AEGIS_RUN_LAUNCHD_TESTS")=="1", "opt-in isolated launchd service")
    def test_launchd_bootout_cleans_watch_scan_group(self):
        self.configure(mode="ignore")
        label="com.aegis.lab.watch."+secrets.token_hex(8)
        domain="system" if os.geteuid()==0 else "gui/"+str(os.geteuid())
        plist=self.root/(label+".plist")
        plist.write_bytes(plistlib.dumps({"Label":label,"ProgramArguments":[sys.executable,str(self.root/"worker.py"),str(self.root)],
                                         "RunAtLoad":True,"KeepAlive":True,"ExitTimeOut":10}))
        try:
            subprocess.run(["/bin/launchctl","bootstrap",domain,str(plist)],check=True,capture_output=True)
            self.wait_for("leaf.pid")
            subprocess.run(["/bin/launchctl","bootout",domain+"/"+label],check=True,capture_output=True)
            self.assertEqual(json.loads(self.wait_for("result.json").read_text()),0)
            self.assert_processes_gone()
        finally:
            subprocess.run(["/bin/launchctl","bootout",domain+"/"+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)


if __name__=="__main__": unittest.main()
