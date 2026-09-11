#!/usr/bin/env python3
"""Fail-closed, privacy-minimized final Aegis production acceptance gate."""
import argparse, hashlib, hmac, json, os, re, stat, sys, time
from pathlib import Path

MAX_EVIDENCE_BYTES=64*1024
MAX_SIGNING_KEYS_BYTES=64*1024
MAX_SIGNING_KEYS=5
MAX_RECORD_BYTES=2*1024*1024
CHECKS={
    "release_verified","ci_gates_passed","collector_probe_passed","collector_backup_restore_tested",
    "deployment_platform_preflight_passed","windows_upgrade_rollback_tested","macos_upgrade_rollback_tested",
    "enterprise_4a_interface_accepted","optional_adapters_disabled_or_accepted","console_read_only_connected",
}
APPROVALS={"security_owner","endpoint_owner","platform_owner","business_owner"}
TOP={"schema","release_version","release_manifest_sha256","git_commit_sha","site_version","generated_at","checks","evidence_files","evidence_sha256","approvals","integrity","secrets_embedded","device_identifiers_embedded"}
SIGNING_KEYS_ENV="AEGIS_PRODUCTION_ACCEPTANCE_SIGNING_KEYS"

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

def record_digest(root,name):
    if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",name): raise ValueError("invalid_evidence_record_name")
    root=Path(root)
    if root.is_symlink() or not root.is_dir() or os.path.realpath(root)!=os.path.abspath(root): raise ValueError("unsafe_evidence_root")
    root_flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0); root_fd=os.open(root,root_flags)
    try:
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode): raise ValueError("unsafe_evidence_root")
        descriptor=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=root_fd)
        try:
            before=os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode): raise ValueError("unsafe_evidence_record")
            data=os.read(descriptor,MAX_RECORD_BYTES+1); after=os.fstat(descriptor)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino): raise ValueError("evidence_record_changed")
            if len(data)>MAX_RECORD_BYTES: raise ValueError("evidence_record_too_large")
            return hashlib.sha256(data).hexdigest()
        finally: os.close(descriptor)
    finally: os.close(root_fd)

def canonical_unsigned(evidence):
    value={key:evidence[key] for key in sorted(set(evidence)-{"integrity"})}
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()

def parse_signing_keys(raw):
    try: value=json.loads(raw)
    except (TypeError,json.JSONDecodeError): raise ValueError("invalid_production_signing_keys")
    if type(value) is not dict or not 1<=len(value)<=MAX_SIGNING_KEYS: raise ValueError("invalid_production_signing_keys")
    result={}
    for key_id,secret in value.items():
        if not isinstance(key_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",key_id) or not isinstance(secret,str) or not 32<=len(secret)<=4096: raise ValueError("invalid_production_signing_keys")
        if secret in result.values(): raise ValueError("duplicate_production_signing_key")
        result[key_id]=secret
    return result

def load_signing_keys(path):
    path=Path(path); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); descriptor=os.open(path,flags)
    try:
        info=os.fstat(descriptor); mode=stat.S_IMODE(info.st_mode); allowed_gids={os.getegid(),*os.getgroups()}
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0,os.geteuid()} or mode not in {0o600,0o640} or (mode==0o640 and info.st_gid not in allowed_gids): raise ValueError("unsafe_production_signing_keyring")
        data=os.read(descriptor,MAX_SIGNING_KEYS_BYTES+1)
        if len(data)>MAX_SIGNING_KEYS_BYTES: raise ValueError("production_signing_keyring_too_large")
        return parse_signing_keys(data.decode("utf-8"))
    finally: os.close(descriptor)

def evaluate(downloads,evidence,evidence_root,expected_git_commit,expected_site_version,signing_keys,now=None):
    downloads=Path(downloads); now=int(time.time()) if now is None else int(now); errors=[]
    if type(evidence) is not dict or set(evidence)!=TOP: return ["invalid_evidence_contract"]
    try: release=json.loads(read_regular_bounded(downloads/"release.json",64*1024))
    except (OSError,ValueError,json.JSONDecodeError): return ["invalid_release_metadata"]
    if evidence.get("schema")!="aegis.production-acceptance/v3": errors.append("invalid_evidence_schema")
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
    evidence_digests=evidence.get("evidence_sha256")
    evidence_files=evidence.get("evidence_files")
    used_files=[]
    if type(evidence_files) is not dict or set(evidence_files)!=CHECKS: errors.append("invalid_evidence_files_contract")
    if type(evidence_digests) is not dict or set(evidence_digests)!=CHECKS: errors.append("invalid_evidence_digests_contract")
    else:
        for name in sorted(CHECKS):
            if not isinstance(evidence_digests[name],str) or not re.fullmatch(r"[0-9a-f]{64}",evidence_digests[name]): errors.append("evidence_digest_missing:"+name)
            if type(evidence_files) is dict and set(evidence_files)==CHECKS:
                if isinstance(evidence_files[name],str): used_files.append(evidence_files[name])
                try: actual=record_digest(evidence_root,evidence_files[name])
                except (OSError,ValueError): errors.append("evidence_record_unavailable:"+name)
                else:
                    if not hmac.compare_digest(actual,evidence_digests[name]): errors.append("evidence_record_mismatch:"+name)
    approvals=evidence.get("approvals")
    if type(approvals) is not dict or set(approvals)!=APPROVALS: errors.append("invalid_approvals_contract")
    else:
        for name in sorted(APPROVALS):
            value=approvals[name]
            if type(value) is not dict or set(value)!={"identity","evidence_file","evidence_sha256"}: errors.append("approval_missing:"+name); continue
            if not isinstance(value["identity"],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}",value["identity"]): errors.append("approval_missing:"+name)
            if not isinstance(value["evidence_sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",value["evidence_sha256"]): errors.append("approval_digest_missing:"+name)
            if isinstance(value["evidence_file"],str): used_files.append(value["evidence_file"])
            try: actual=record_digest(evidence_root,value["evidence_file"])
            except (OSError,ValueError): errors.append("approval_record_unavailable:"+name)
            else:
                if isinstance(value["evidence_sha256"],str) and re.fullmatch(r"[0-9a-f]{64}",value["evidence_sha256"]) and not hmac.compare_digest(actual,value["evidence_sha256"]): errors.append("approval_record_mismatch:"+name)
    if len(used_files)!=len(set(used_files)): errors.append("duplicate_evidence_record")
    integrity=evidence.get("integrity")
    if type(integrity) is not dict or set(integrity)!={"algorithm","key_id","signature"} or integrity.get("algorithm")!="hmac-sha256" or not isinstance(integrity.get("key_id"),str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",integrity["key_id"]) or not isinstance(integrity.get("signature"),str) or not re.fullmatch(r"[0-9a-f]{64}",integrity["signature"]): errors.append("invalid_production_signature")
    elif integrity["key_id"] not in signing_keys: errors.append("unknown_production_signing_key")
    else:
        expected=hmac.new(signing_keys[integrity["key_id"]].encode(),canonical_unsigned(evidence),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,integrity["signature"]): errors.append("invalid_production_signature")
    if evidence.get("secrets_embedded") is not False: errors.append("secrets_must_not_be_embedded")
    if evidence.get("device_identifiers_embedded") is not False: errors.append("device_identifiers_must_not_be_embedded")
    return errors

def main():
    parser=argparse.ArgumentParser();parser.add_argument("evidence");parser.add_argument("--downloads",default=Path(__file__).parent);parser.add_argument("--evidence-root",required=True);parser.add_argument("--expected-git-commit",required=True);parser.add_argument("--expected-site-version",required=True,type=int);parser.add_argument("--keyring");args=parser.parse_args()
    try: evidence=json.loads(read_regular_bounded(args.evidence,MAX_EVIDENCE_BYTES))
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"errors":[type(exc).__name__]},separators=(",",":")));return 2
    try: signing_keys=load_signing_keys(args.keyring) if args.keyring else parse_signing_keys(os.getenv(SIGNING_KEYS_ENV,""))
    except ValueError as exc: print(json.dumps({"ok":False,"errors":[str(exc)]},separators=(",",":")));return 2
    errors=evaluate(args.downloads,evidence,args.evidence_root,args.expected_git_commit,args.expected_site_version,signing_keys);print(json.dumps({"ok":not errors,"errors":errors},separators=(",",":")));return 0 if not errors else 2
if __name__=="__main__": sys.exit(main())
