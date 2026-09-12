#!/usr/bin/env python3
"""Build a Aegis release deterministically from the checked-in sources."""
import argparse, hashlib, json, os, re, shutil, stat, sys, tempfile, zipfile
from datetime import datetime
from pathlib import Path

sys.dont_write_bytecode=True
import aegis_release_verify as verifier

GENERATED_FILES={"CHECKSUMS.sha256","RELEASE-MANIFEST.sha256","mdm-deployment-manifest.json","mdm-rollout-evidence.example.json","production-acceptance-evidence.example.json","aegis-enterprise-bundle.zip","update-manifest.json"}

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def require_regular(path):
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode): raise ValueError("unsafe_release_input:"+path.name)
    return info

def atomic_write(path,data):
    info=require_regular(path) if path.exists() or path.is_symlink() else None
    fd,name=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
    try:
        if info: os.fchmod(fd,stat.S_IMODE(info.st_mode))
        with os.fdopen(fd,"wb") as handle: fd=-1; handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
    finally:
        if fd>=0: os.close(fd)
        try: os.unlink(name)
        except FileNotFoundError: pass

def replace_digest(path,old,new):
    data=path.read_bytes()
    if old==new: return
    needle=old.encode("ascii")
    if needle not in data: raise ValueError("embedded_digest_not_found:"+path.name)
    atomic_write(path,data.replace(needle,new.encode("ascii")))

def zip_timestamp(release):
    value=datetime.fromisoformat(release["published_at"])
    year=max(value.year,1980)
    return (year,value.month,value.day,value.hour,value.minute,value.second-(value.second%2))

def build(downloads):
    downloads=Path(downloads)
    if downloads.is_symlink() or not downloads.is_dir(): raise ValueError("unsafe_downloads_directory")
    for name in (set(verifier.BUNDLE_FILES) | {"aegis-enterprise-bundle.zip"}) - GENERATED_FILES: require_regular(downloads/name)
    release=json.loads((downloads/"release.json").read_text(encoding="utf-8"))
    manifest_path=downloads/"mdm-deployment-manifest.json"
    deployment=json.loads(manifest_path.read_text(encoding="utf-8"))
    if deployment.get("execution",{}).get("script_signature_state")!="pilot_unsigned":
        raise ValueError("signed_release_must_be_rebuilt_on_signing_workstation")

    old={}
    for line in (downloads/"CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines():
        parts=line.split()
        if len(parts)==2 and re.fullmatch(r"[0-9a-f]{64}",parts[0]): old[parts[1]]=parts[0]
    if set(old)!=set(verifier.RUNTIME_FILES): raise ValueError("invalid_existing_checksum_manifest")
    current={name:digest(downloads/name) for name in verifier.RUNTIME_FILES}
    for name,consumers in verifier.HASH_CONSUMERS.items():
        for consumer in consumers: replace_digest(downloads/consumer,old[name],current[name])
    atomic_write(downloads/"CHECKSUMS.sha256","".join(f"{current[name]}  {name}\n" for name in verifier.RUNTIME_FILES).encode())

    # 客户端自更新清单（无桌管环境兜底通道；主通道为桌管/MDM 推送）。
    atomic_write(downloads/"update-manifest.json",(json.dumps({
        "schema":"aegis.update/v1",
        "release":release["release"],
        "channel":release.get("channel","pilot"),
        "published_at":release.get("published_at",""),
        "min_agent_version":release.get("min_agent_version","0.30.0"),
        "artifacts":{
            "aegis_agent.py":{"url":"/downloads/aegis_agent.py","sha256":current["aegis_agent.py"]},
            "aegis-windows.ps1":{"url":"/downloads/aegis-windows.ps1","sha256":current["aegis-windows.ps1"]},
            "aegis_self_update.py":{"url":"/downloads/aegis_self_update.py","sha256":digest(downloads/"aegis_self_update.py")},
        },
    },ensure_ascii=False,indent=2)+"\n").encode())

    for artifact in deployment["artifacts"].values(): artifact["sha256"]=digest(downloads/artifact["file"])
    atomic_write(manifest_path,(json.dumps(deployment,ensure_ascii=False,indent=2)+"\n").encode())
    evidence_path=downloads/"mdm-rollout-evidence.example.json"
    evidence=json.loads(evidence_path.read_text(encoding="utf-8")); evidence["release_version"]=release["release"]; evidence["manifest_sha256"]=digest(manifest_path)
    atomic_write(evidence_path,(json.dumps(evidence,ensure_ascii=False,indent=2)+"\n").encode())
    production_path=downloads/"production-acceptance-evidence.example.json"
    production=json.loads(production_path.read_text(encoding="utf-8")); production["release_version"]=release["release"]
    atomic_write(production_path,(json.dumps(production,ensure_ascii=False,indent=2)+"\n").encode())

    full_manifest="".join(f"{digest(downloads/name)}  {name}\n" for name in sorted(verifier.RELEASE_MANIFEST_FILES))
    atomic_write(downloads/"RELEASE-MANIFEST.sha256",full_manifest.encode())

    output=downloads/"aegis-enterprise-bundle.zip"; descriptor,temporary_name=tempfile.mkstemp(prefix=".aegis-bundle.",suffix=".zip",dir=downloads); os.close(descriptor); temporary=Path(temporary_name)
    stamp=zip_timestamp(release)
    with zipfile.ZipFile(temporary,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
        for name in sorted(verifier.BUNDLE_FILES):
            data=(downloads/name).read_bytes(); info=zipfile.ZipInfo(name,stamp); info.compress_type=zipfile.ZIP_DEFLATED; info.create_system=3; info.external_attr=0o100644<<16
            bundle.writestr(info,data,compresslevel=9)
    os.chmod(temporary,0o644)
    os.replace(temporary,output)
    directory=os.open(downloads,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
    errors=verifier.verify(downloads)
    if errors: raise ValueError("release_verification_failed:"+",".join(errors))

def check(downloads):
    downloads=Path(downloads)
    with tempfile.TemporaryDirectory(prefix="aegis-release-check-") as directory:
        candidate=Path(directory)
        for source in downloads.iterdir():
            if source.is_file(): shutil.copy2(source,candidate/source.name)
        build(candidate)
        compared=GENERATED_FILES|{item for values in verifier.HASH_CONSUMERS.values() for item in values}
        drift=sorted(name for name in compared if (downloads/name).read_bytes()!=(candidate/name).read_bytes())
        if drift: raise ValueError("release_build_drift:"+",".join(drift))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("downloads",nargs="?",default=str(Path(__file__).parent)); parser.add_argument("--check",action="store_true"); args=parser.parse_args()
    try: check(args.downloads) if args.check else build(args.downloads); print(json.dumps({"ok":True,"mode":"check" if args.check else "build"},separators=(",",":"))); return 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError,zipfile.BadZipFile) as exc:
        print(json.dumps({"ok":False,"error":str(exc)},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
