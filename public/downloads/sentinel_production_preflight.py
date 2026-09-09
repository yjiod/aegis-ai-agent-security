#!/usr/bin/env python3
"""Fail-closed, privacy-minimized final Sentinel production acceptance gate."""
import argparse, hashlib, hmac, json, os, re, stat, sys, time
from pathlib import Path

MAX_EVIDENCE_BYTES=64*1024
CHECKS={
    "release_verified","ci_gates_passed","collector_probe_passed","collector_backup_restore_tested",
    "intune_production_preflight_passed","windows_upgrade_rollback_tested","macos_upgrade_rollback_tested",
    "sangfor_acceptance_v3_passed","leagsoft_acceptance_v3_passed","console_read_only_connected",
}
APPROVALS={"security_owner","endpoint_owner","platform_owner","business_owner"}
TOP={"schema","release_version","release_manifest_sha256","git_commit_sha","site_version","generated_at","checks","approvals","secrets_embedded","device_identifiers_embedded"}

def read_regular_bounded(path,limit):
    path=Path(path); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); descriptor=os.open(path,flags)
    try:
        before=os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode): raise ValueError("unsafe_evidence_file")
        data=os.read(descriptor,limit+1); after=os.fstat(descriptor)
        if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino): raise ValueError("evidence_file_changed")
        if len(data)>limit: raise ValueError("evidence_too_large")
        return data
    finally: os.close(descriptor)

def digest(path): return hashlib.sha256(read_regular_bounded(path,2*1024*1024)).hexdigest()

def evaluate(downloads,evidence,expected_git_commit,expected_site_version,now=None):
    downloads=Path(downloads); now=int(time.time()) if now is None else int(now); errors=[]
    if type(evidence) is not dict or set(evidence)!=TOP: return ["invalid_evidence_contract"]
    try: release=json.loads(read_regular_bounded(downloads/"release.json",64*1024))
    except (OSError,ValueError,json.JSONDecodeError): return ["invalid_release_metadata"]
    if evidence.get("schema")!="sentinel.production-acceptance/v1": errors.append("invalid_evidence_schema")
    if evidence.get("release_version")!=release.get("release"): errors.append("release_version_mismatch")
    try: manifest_digest=digest(downloads/"RELEASE-MANIFEST.sha256")
    except (OSError,ValueError): errors.append("invalid_release_manifest"); manifest_digest=""
    supplied=evidence.get("release_manifest_sha256")
    if not isinstance(supplied,str) or not re.fullmatch(r"[0-9a-f]{64}",supplied) or not hmac.compare_digest(supplied,manifest_digest): errors.append("release_manifest_mismatch")
    if not isinstance(expected_git_commit,str) or not re.fullmatch(r"[0-9a-f]{40}",expected_git_commit): errors.append("invalid_expected_git_commit")
    if not isinstance(evidence.get("git_commit_sha"),str) or not re.fullmatch(r"[0-9a-f]{40}",evidence["git_commit_sha"]): errors.append("invalid_git_commit_sha")
    elif isinstance(expected_git_commit,str) and re.fullmatch(r"[0-9a-f]{40}",expected_git_commit) and not hmac.compare_digest(evidence["git_commit_sha"],expected_git_commit): errors.append("git_commit_mismatch")
    if type(expected_site_version) is not int or expected_site_version<1: errors.append("invalid_expected_site_version")
    if type(evidence.get("site_version")) is not int or evidence["site_version"]<1: errors.append("invalid_site_version")
    elif type(expected_site_version) is int and expected_site_version>=1 and evidence["site_version"]!=expected_site_version: errors.append("site_version_mismatch")
    generated=evidence.get("generated_at")
    if type(generated) is not int or generated>now+300 or generated<now-86400: errors.append("stale_or_future_evidence")
    checks=evidence.get("checks")
    if type(checks) is not dict or set(checks)!=CHECKS: errors.append("invalid_checks_contract")
    else:
        for name in sorted(CHECKS):
            if checks[name] is not True: errors.append("gate_failed:"+name)
    approvals=evidence.get("approvals")
    if type(approvals) is not dict or set(approvals)!=APPROVALS: errors.append("invalid_approvals_contract")
    else:
        for name in sorted(APPROVALS):
            value=approvals[name]
            if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}",value): errors.append("approval_missing:"+name)
    if evidence.get("secrets_embedded") is not False: errors.append("secrets_must_not_be_embedded")
    if evidence.get("device_identifiers_embedded") is not False: errors.append("device_identifiers_must_not_be_embedded")
    return errors

def main():
    parser=argparse.ArgumentParser();parser.add_argument("evidence");parser.add_argument("--downloads",default=Path(__file__).parent);parser.add_argument("--expected-git-commit",required=True);parser.add_argument("--expected-site-version",required=True,type=int);args=parser.parse_args()
    try: evidence=json.loads(read_regular_bounded(args.evidence,MAX_EVIDENCE_BYTES))
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"errors":[type(exc).__name__]},separators=(",",":")));return 2
    errors=evaluate(args.downloads,evidence,args.expected_git_commit,args.expected_site_version);print(json.dumps({"ok":not errors,"errors":errors},separators=(",",":")));return 0 if not errors else 2
if __name__=="__main__": sys.exit(main())
