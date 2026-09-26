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
  - 同源钉子：manifest 里相对的工件 url 按 manifest 源解析为绝对地址，且解析后
    scheme+netloc 必须与 manifest 一致——未签名 manifest 即便被中间人替换，也无法
    把下载改指向恶意主机（见 resolve_artifact_url）。
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import tempfile
import urllib.request
from urllib.parse import urljoin, urlsplit

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


def resolve_artifact_url(manifest_url: str, art_url: str) -> str:
    """把 manifest 里的工件 URL 解析为绝对地址，并**强制同源**。

    发行 manifest 的工件 url 是相对路径（如 /downloads/aegis_agent.py）；此前直接喂给
    download_and_verify 会因不匹配 https:// 前缀被拒，令自更新兜底通道静默失效。此处按
    manifest_url 用 urljoin 还原绝对地址修复之。

    同时做同源钉子（scheme + netloc 必须与 manifest 一致）：manifest 目前**未签名**，
    若被中间人替换，攻击者可将工件 url 指向自有主机并配上匹配的 sha256 绕过完整性校验。
    同源约束把下载面锁死在 manifest 来源，未签名 manifest 也无法被改指向恶意主机。
    file:// 仅当 manifest 本身即 file://（本地测试）时允许。
    """
    base = urlsplit(str(manifest_url))
    joined = urljoin(str(manifest_url), str(art_url))
    j = urlsplit(joined)
    if j.scheme not in ("https", "file"):
        raise ValueError("update_artifact_scheme_not_allowed")
    if j.scheme != base.scheme or j.netloc != base.netloc:
        raise ValueError("update_artifact_origin_mismatch")
    return joined


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
    """原子替换 target；旧版本备份为 target.prev。返回备份路径。

    关键：保留 target 原有权限位。staging 来自 mkstemp(0600)，os.replace 后 target 会丢掉
    可执行位——对 python 脚本形态(经 python3 解释执行)无碍，但对**冻结二进制**形态是致命的：
    LaunchAgent/systemd 直接 exec 该文件，丢了 +x 就 "permission denied"、下一周期起不来、
    agent 变砖。故替换前记录原 mode、替换后 chmod 回去（无原文件则给 0755）。
    """
    backup = target + ".prev"
    orig_mode = None
    if os.path.exists(target):
        try:
            orig_mode = os.stat(target).st_mode & 0o777
        except OSError:
            orig_mode = None
        # 复制当前版本到 backup（不用 rename，保留 target 直到 replace）
        with open(target, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
    os.replace(staging, target)
    try:
        os.chmod(target, orig_mode if orig_mode is not None else 0o755)
    except OSError:
        pass
    return backup


def rollback(target: str) -> bool:
    """若存在 target.prev 则回退；返回是否回退。"""
    backup = target + ".prev"
    if not os.path.exists(backup):
        return False
    os.replace(backup, target)
    return True


def _safe_remove(path: str) -> None:
    """删除 Agent 自更新过程中自己产生的 staging 临时件（非用户文件）；失败忽略。"""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def preflight_script(path: str) -> bool:
    """.py 工件的内置 preflight：语法可解析即视为健康。
    sha256 已保证字节与发布件逐位一致，故这里能挡住的正是"发布件自身语法损坏/被截断"
    这类会让 agent 下次启动即崩、把机队更新成砖的极端情况。"""
    try:
        with open(path, "rb") as fh:
            ast.parse(fh.read())
        return True
    except (OSError, SyntaxError, ValueError):
        return False


def default_preflight(target_path: str, staging: str) -> bool:
    """未显式传 preflight 钩子时的内置校验：仅对 .py 目标做语法解析；其它形态（冻结二进制）
    无法在更新器内廉价校验，返回 True，由"应用后 sha256 复核 + 自动回滚"兜底。
    冻结二进制形态应由调用方传入 exec `--selftest` 的钩子（见 aegis_agent.maybe_self_update）。"""
    if str(target_path).endswith(".py"):
        return preflight_script(staging)
    return True


def check_and_apply(
    manifest_url: str,
    current_version: str,
    device_id: str,
    artifact_name: str,
    target_path: str,
    rollout_percent: int = 100,
    preflight=None,
) -> dict:
    """
    端到端：拉 manifest → 版本/灰度判断 → 下载校验 → preflight 校验 → 原子替换 → 应用后复核。
    返回 {"updated": bool, "from":..., "to":..., "reason":...}。任何失败不抛、返回原因。

    健壮性（PM#2 · 绝不把机队更新成砖）：
      - preflight（替换**前**）：校验下载到 staging 的新工件；不通过则拒绝、保留旧版本
        （reason=preflight_failed）。钩子由调用方注入（冻结二进制传"exec --selftest"），
        缺省对 .py 目标做语法解析；钩子自身异常一律 fail-closed（拒绝更新）。
      - 应用后复核（替换**后**）：重算 target 的 sha256，与工件期望不符即自动 rollback 到
        .prev（reason=rolled_back:sha_mismatch），确保替换绝不产出比原来更糟的状态。
    """
    try:
        manifest = fetch_manifest(manifest_url)
    except Exception as e:  # noqa: BLE001 - report reason, never crash scan
        return {"updated": False, "reason": "manifest_fetch_failed:" + type(e).__name__}
    release = str(manifest.get("release", ""))
    # 'release' 是发行包版本轴，current_version 是 Agent 版本轴；直接比较会让 is_newer
    # 恒为真、每轮扫描都重复下载替换。优先用 manifest 的 agent_version（与本轴一致）。
    offered = str(manifest.get("agent_version") or release)
    if not offered or not is_newer(offered, current_version):
        return {"updated": False, "reason": "up_to_date", "current": current_version, "latest": offered}
    if not in_rollout(device_id, rollout_percent):
        return {"updated": False, "reason": "not_in_rollout", "latest": offered}
    staging = target_path + ".staging"
    try:
        art = manifest_artifact(manifest, artifact_name)
        # 幂等短路：本地文件已是目标 sha256 → 无需重复下载/原子替换（防版本轴错配 churn）。
        if os.path.isfile(target_path):
            with open(target_path, "rb") as fh:
                local_sha = hashlib.sha256(fh.read()).hexdigest()
            if local_sha == art.get("sha256"):
                return {"updated": False, "reason": "already_current", "current": current_version, "latest": offered}
        # 相对工件 url 按 manifest 源解析为绝对地址并强制同源（见 resolve_artifact_url）。
        artifact_url = resolve_artifact_url(manifest_url, art["url"])
        download_and_verify(artifact_url, art["sha256"], staging)
        # preflight：替换前校验新工件；不通过即拒绝、保留旧版本（staging 清理掉）。
        try:
            healthy = preflight(staging) if callable(preflight) else default_preflight(target_path, staging)
        except Exception:  # noqa: BLE001 - 钩子异常 fail-closed，宁可 stays-old 也不冒险替换
            healthy = False
        if not healthy:
            _safe_remove(staging)
            return {"updated": False, "reason": "preflight_failed", "current": current_version, "latest": offered}
        apply_update(staging, target_path)
        # 应用后复核：target 的 sha256 必须等于期望；不符则自动回滚（绝不留在坏状态）。
        try:
            with open(target_path, "rb") as fh:
                applied_sha = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            applied_sha = ""
        if applied_sha != art.get("sha256"):
            rolled = rollback(target_path)
            return {
                "updated": False,
                "reason": "rolled_back:sha_mismatch" if rolled else "apply_verify_failed",
                "current": current_version,
                "latest": offered,
            }
    except Exception as e:  # noqa: BLE001
        _safe_remove(staging)
        return {"updated": False, "reason": "apply_failed:" + type(e).__name__, "latest": offered}
    return {"updated": True, "from": current_version, "to": offered, "reason": "ok", "sha256": applied_sha}
