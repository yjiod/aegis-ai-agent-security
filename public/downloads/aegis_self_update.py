#!/usr/bin/env python3
"""
Aegis 客户端自更新（无桌管环境兜底通道）。

主通道永远是桌管/MDM 推送；本模块仅在无桌管环境时由 Agent 自检更新。
安全约束：
  - 只替换 Agent 自身脚本文件，不执行下载内容（下次运行自然生效）。
  - 下载后必须 SHA-256 校验通过才允许原子替换；校验失败拒绝并保留旧版本。
  - 原子替换：先写 staging 临时文件再 os.replace；替换前把当前版本备份为
    <target>.prev，并提供 rollback() 回退。
  - 灰度：按 device_id 的稳定哈希 % 100 < rollout_percent 才更新。
  - 仅允许 https:// 与 file:// （file 仅用于本地测试）源。
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request

UPDATE_SCHEMA = "aegis.update/v1"
ALLOWED_SCHEMES = ("https://", "file://")


def version_tuple(v: str) -> tuple:
    """'0.31.0' -> (0,31,0)；非数字段按 0。"""
    out = []
    for part in str(v).split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def is_newer(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)


def in_rollout(device_id: str, rollout_percent: int) -> bool:
    """按 device_id 稳定哈希灰度；rollout_percent<=0 不放量, >=100 全量。"""
    pct = max(0, min(100, int(rollout_percent)))
    if pct >= 100:
        return True
    if pct <= 0:
        return False
    h = int(hashlib.sha256(str(device_id).encode()).hexdigest(), 16)
    return (h % 100) < pct


def fetch_manifest(url: str, timeout: int = 15) -> dict:
    if not str(url).startswith(ALLOWED_SCHEMES):
        raise ValueError("update_manifest_scheme_not_allowed")
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec: scheme allowlisted
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict) or data.get("schema") != UPDATE_SCHEMA:
        raise ValueError("invalid_update_manifest")
    return data


def manifest_artifact(manifest: dict, name: str) -> dict:
    arts = manifest.get("artifacts", {})
    if not isinstance(arts, dict) or name not in arts:
        raise ValueError("update_artifact_missing:" + name)
    art = arts[name]
    if not isinstance(art, dict) or not isinstance(art.get("sha256"), str) or not art.get("url"):
        raise ValueError("invalid_update_artifact:" + name)
    return art


def download_and_verify(url: str, sha256: str, dest_staging: str, timeout: int = 60) -> str:
    """下载到 staging 并校验 sha256；失败抛异常且不留半成品。"""
    if not str(url).startswith(ALLOWED_SCHEMES):
        raise ValueError("update_artifact_scheme_not_allowed")
    fd, tmp = tempfile.mkstemp(prefix=".aegis-update-", dir=os.path.dirname(dest_staging) or ".")
    os.close(fd)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec: scheme allowlisted
            body = resp.read()
        if hashlib.sha256(body).hexdigest() != sha256.lower():
            raise ValueError("update_sha256_mismatch")
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, dest_staging)
        return dest_staging
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def apply_update(staging: str, target: str) -> str:
    """原子替换 target；旧版本备份为 target.prev。返回备份路径。"""
    backup = target + ".prev"
    if os.path.exists(target):
        # 复制当前版本到 backup（不用 rename，保留 target 直到 replace）
        with open(target, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
    os.replace(staging, target)
    return backup


def rollback(target: str) -> bool:
    """若存在 target.prev 则回退；返回是否回退。"""
    backup = target + ".prev"
    if not os.path.exists(backup):
        return False
    os.replace(backup, target)
    return True


def check_and_apply(
    manifest_url: str,
    current_version: str,
    device_id: str,
    artifact_name: str,
    target_path: str,
    rollout_percent: int = 100,
) -> dict:
    """
    端到端：拉 manifest → 版本/灰度判断 → 下载校验 → 原子替换。
    返回 {"updated": bool, "from":..., "to":..., "reason":...}。任何失败不抛、返回原因。
    """
    try:
        manifest = fetch_manifest(manifest_url)
    except Exception as e:  # noqa: BLE001 - report reason, never crash scan
        return {"updated": False, "reason": "manifest_fetch_failed:" + type(e).__name__}
    release = str(manifest.get("release", ""))
    if not release or not is_newer(release, current_version):
        return {"updated": False, "reason": "up_to_date", "current": current_version, "latest": release}
    if not in_rollout(device_id, rollout_percent):
        return {"updated": False, "reason": "not_in_rollout", "latest": release}
    try:
        art = manifest_artifact(manifest, artifact_name)
        staging = target_path + ".staging"
        download_and_verify(art["url"], art["sha256"], staging)
        apply_update(staging, target_path)
    except Exception as e:  # noqa: BLE001
        return {"updated": False, "reason": "apply_failed:" + type(e).__name__, "latest": release}
    return {"updated": True, "from": current_version, "to": release, "reason": "ok"}
