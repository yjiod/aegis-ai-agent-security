#!/usr/bin/env python3
"""Validate vendor-neutral unified identity/4A integration registrations."""
import argparse, importlib.util, ipaddress, json, re, sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES=262_144

def load_contract():
    spec=importlib.util.spec_from_file_location("sentinel_4a_interface",Path(__file__).with_name("sentinel_4a_interface.py"))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

def validate(data):
    contract=load_contract(); errors=[]
    if not isinstance(data,dict) or set(data)!={"schema","providers"} or data.get("schema")!="sentinel.integration-registry/v1": return ["invalid_registry_contract"]
    providers=data.get("providers")
    if not isinstance(providers,list) or not 1<=len(providers)<=64: return ["invalid_provider_count"]
    seen=set()
    for index,item in enumerate(providers):
        prefix=f"provider:{index}"
        if not isinstance(item,dict) or set(item)!={"provider_id","enabled","endpoint_url","auth","capabilities","approval_enforced"}: errors.append(prefix+":invalid_fields"); continue
        provider_id=item.get("provider_id")
        if not isinstance(provider_id,str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}",provider_id) or provider_id in seen: errors.append(prefix+":invalid_provider_id"); continue
        seen.add(provider_id)
        if type(item.get("enabled")) is not bool or type(item.get("approval_enforced")) is not bool: errors.append(prefix+":invalid_boolean")
        auth=item.get("auth")
        if not isinstance(auth,dict) or set(auth)!={"scheme","credential_env"} or auth.get("scheme") not in {"bearer","oauth2_client_credentials","mtls"} or not re.fullmatch(r"SENTINEL_[A-Z0-9_]{3,100}",str(auth.get("credential_env",""))): errors.append(prefix+":invalid_auth")
        parsed=urlsplit(item.get("endpoint_url","") if isinstance(item.get("endpoint_url"),str) else "")
        try:
            host=parsed.hostname or ""
            ipaddress.ip_address(host); host_is_ip=True
        except ValueError: host_is_ip=False
        if parsed.scheme!="https" or not host or parsed.username or parsed.password or parsed.query or parsed.fragment or host_is_ip: errors.append(prefix+":unsafe_endpoint")
        raw=item.get("capabilities")
        try: capabilities=frozenset(contract.Capability(value) for value in raw) if isinstance(raw,list) and len(raw)==len(set(raw)) else frozenset()
        except (TypeError,ValueError): capabilities=frozenset()
        try: contract.validate_descriptor(contract.ProviderDescriptor(provider_id,capabilities,approval_enforced=item.get("approval_enforced")))
        except ValueError as exc: errors.append(prefix+":"+str(exc))
    return list(dict.fromkeys(errors))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("registry"); args=parser.parse_args()
    try:
        raw=Path(args.registry).read_bytes()
        if len(raw)>MAX_BYTES: raise ValueError("oversized_registry")
        data=json.loads(raw.decode("utf-8")); errors=validate(data)
    except (OSError,UnicodeError,ValueError,TypeError) as exc: errors=["invalid_registry:"+type(exc).__name__]
    print(json.dumps({"ok":not errors,"errors":errors},ensure_ascii=False,separators=(",",":"))); return 1 if errors else 0

if __name__=="__main__": sys.exit(main())
