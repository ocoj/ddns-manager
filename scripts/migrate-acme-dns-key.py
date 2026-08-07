#!/usr/bin/env python3
"""migrate-acme-dns-key.py — 为存量 ACME 证书的 meta.json 登记 DNS Key 名。

背景
----
修复前 meta.json 只记录 provider（如 alidns），不记录实际使用的 DNS Key 名。
同厂商存在多把 Key 时，续期无法确定该用哪一把（生产现场 alidns 有 3 条记录），
只能回退到 acme.sh 的全局 account.conf —— 这正是自动续期失效的根因之一。

本脚本把"Key 名"补写进 meta.dns_key，使续期可精确取用。

安全设计
--------
* 默认 dry-run，只有 --apply 才写盘；
* 只处理 meta.json 中 "acme": true 的证书，用户上传证书一律不动；
* 只做"新增/修正 dns_key"这一件事，其余字段原样保留；
* 同一 provider 存在多个候选时默认跳过（歧义），--force 才允许覆盖已有 dns_key；
* 写盘前先备份 certs/ 与 dns_keys.json；
* 原子写（mkstemp + os.replace）并保留原 uid/gid/权限；
* --verify 校验：① 所有 ACME meta 均含 dns_key 且 Key 存在、provider 一致；
  ② 所有 ACME 证书的 acme.sh 安装路径（Le_Real*Path）等于其 bundle 目录。

用法
----
  # 预演（只读，打印将要做的修改）
  python3 scripts/migrate-acme-dns-key.py --certs-dir /path/to/data/certs \
      --key-name '权威Key名'

  # 落盘
  python3 scripts/migrate-acme-dns-key.py --certs-dir /path/to/data/certs \
      --key-name '权威Key名' --apply

  # 校验（退出码 0 表示全部通过）
  python3 scripts/migrate-acme-dns-key.py --certs-dir /path/to/data/certs \
      --key-name '权威Key名' --verify

退出码: 0 成功 / 1 参数或数据错误 / 2 校验失败
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import sys
import tempfile
import time

ACME_SH_HOME = os.environ.get("ACME_SH_HOME", "/root/.acme.sh")


def log(msg: str) -> None:
    print(msg, flush=True)


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def backup(paths, label: str) -> str:
    dest = "%s.bak-%s-%s" % (paths[0].rstrip("/"), label, time.strftime("%Y%m%d-%H%M%S"))
    for p in paths:
        if not os.path.exists(p):
            continue
        dst = os.path.join(dest, os.path.basename(p.rstrip("/")))
        if os.path.isdir(p):
            shutil.copytree(p, dst)
        else:
            shutil.copy2(p, dst)
    return dest


def atomic_write_json(path: str, data) -> None:
    """原子写 JSON，保留原文件 uid/gid/mode。"""
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".meta-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# 与 Go 侧 internal/acme.dnsAPIMapping 对齐：secret 字段非空的 provider 必须
# 同时具备 access_key_secret，否则 Go 侧 resolveDNSKey 会判定"凭据不完整"。
# 若此处口径更宽，脚本可能把 Go 认为不可用的 Key 当作唯一候选写入 dns_key（B7）。
REQUIRES_SECRET = {
    "alidns", "txcloud", "tencentcloud", "dnspod",
    "huawei", "huaweicloud", "godaddy", "porkbun", "namecheap",
}


def _needs_secret(provider: str) -> bool:
    return provider.strip().lower() in REQUIRES_SECRET


def _credential_problem(rec: dict) -> str:
    """返回该 Key 的凭据问题（完整则返回空串）。

    必须与 Go 侧 resolveDNSKey 的"凭据完整"口径一致：命中但凭据不完整的
    dns_key 会让 Go 直接拒绝注入，**且不会回退**"同厂商唯一匹配"兜底 ——
    因此写入不完整的 Key 名比留空更糟（等于退回 account.conf，即本次故障状态）。
    """
    provider = str(rec.get("provider", "")).strip()
    if not provider:
        return "缺少 provider 字段"
    if not rec.get("access_key_id"):
        return "缺少 access_key_id"
    if _needs_secret(provider) and not rec.get("access_key_secret"):
        return "provider=%s 需要 access_key_secret，但为空" % provider
    return ""


def resolve_candidates(keys: dict, provider: str):
    """返回该 provider 下"凭据完整"的 Key 名列表。"""
    out = []
    for name, rec in keys.items():
        if str(rec.get("provider", "")).lower() != provider.lower():
            continue
        if _credential_problem(rec):
            continue
        out.append(name)
    return sorted(out)


def cmd_verify(certs_dir: str, keys: dict) -> int:
    rc = 0
    metas = sorted(glob.glob(os.path.join(certs_dir, "acme-*", "meta.json")))
    if not metas:
        log("[verify] ❌ 未找到任何 acme-* 证书")
        return 2

    for mp in metas:
        bundle = os.path.dirname(mp)
        name = os.path.basename(bundle)
        try:
            meta = load_json(mp)
        except Exception as e:  # noqa: BLE001
            log("[verify] ❌ %s meta.json 无法解析: %s" % (name, e))
            rc = 2
            continue
        if not meta.get("acme"):
            log("[verify] ⏭  %s 非 ACME 证书，跳过" % name)
            continue

        # ① dns_key 已登记且一致
        key_name = str(meta.get("dns_key", ""))
        provider = str(meta.get("provider", ""))
        if not key_name:
            log("[verify] ❌ %s 缺少 meta.dns_key" % name)
            rc = 2
        elif key_name not in keys:
            log("[verify] ❌ %s 的 dns_key=%r 不存在于 dns_keys.json" % (name, key_name))
            rc = 2
        elif str(keys[key_name].get("provider", "")).lower() != provider.lower():
            log("[verify] ❌ %s dns_key=%r 的 provider(%s) 与 meta.provider(%s) 不一致"
                % (name, key_name, keys[key_name].get("provider"), provider))
            rc = 2
        elif _credential_problem(keys[key_name]):
            log("[verify] ❌ %s dns_key=%r 凭据不完整：%s（续期将不会注入凭据）"
                % (name, key_name, _credential_problem(keys[key_name])))
            rc = 2
        else:
            log("[verify] ✅ %s dns_key=%r provider=%s" % (name, key_name, provider))

        # ② acme.sh 安装路径 == bundle 目录
        domains = meta.get("domains") or []
        if not domains:
            log("[verify] ❌ %s meta.domains 为空，无法校验安装路径" % name)
            rc = 2
            continue
        primary = domains[0]
        confs = glob.glob(os.path.join(ACME_SH_HOME, "%s*" % primary, "*.conf"))
        confs = [c for c in confs if not c.endswith(".csr.conf")]
        if not confs:
            log("[verify] ⚠️  %s 未找到 acme.sh conf（%s/%s*），跳过路径校验"
                % (name, ACME_SH_HOME, primary))
            continue
        bad = []
        with open(confs[0], encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^\s*Le_Real(Cert|Key|FullChain)Path='(.*)'\s*$", line)
                if not m:
                    continue
                # 生产上 Le_Real*Path 指向 bundle 内的文件（.../acme-x/cert.pem），
                # 因此比较其所在目录，而不是路径本身。
                got_dir = os.path.dirname(os.path.normpath(m.group(2)))
                if got_dir != os.path.normpath(bundle):
                    bad.append((m.group(1), m.group(2)))
        if bad:
            log("[verify] ❌ %s 安装路径与 bundle 不一致: %s" % (name, bad))
            rc = 2
        else:
            log("[verify] ✅ %s 安装路径 == bundle 目录" % name)
    return rc


def cmd_migrate(certs_dir: str, key_name: str, keys: dict, apply: bool, force: bool) -> int:
    metas = sorted(glob.glob(os.path.join(certs_dir, "acme-*", "meta.json")))
    if not metas:
        log("❌ 未找到任何 acme-* 证书")
        return 1
    if key_name not in keys:
        log("❌ --key-name %r 不存在于 dns_keys.json" % key_name)
        return 1
    target_provider = str(keys[key_name].get("provider", ""))
    if not target_provider:
        log("❌ --key-name %r 缺少 provider 字段" % key_name)
        return 1
    problem = _credential_problem(keys[key_name])
    if problem:
        log("❌ --key-name %r 凭据不完整：%s" % (key_name, problem))
        log("   说明：写入凭据不完整的 Key 名【比留空更糟】—— Go 侧 resolveDNSKey 命中后会"
            "直接拒绝注入凭据，且不会回退\"同厂商唯一匹配\"兜底，结果等同退回 account.conf。")
        log("   请先补全该 Key 的凭据（或改用一把完整的 Key），再执行迁移。")
        return 1

    planned = []
    for mp in metas:
        bundle = os.path.dirname(mp)
        name = os.path.basename(bundle)
        try:
            meta = load_json(mp)
        except Exception as e:  # noqa: BLE001
            log("❌ %s meta.json 无法解析: %s" % (name, e))
            return 1
        if not meta.get("acme"):
            continue
        provider = str(meta.get("provider", ""))
        current = str(meta.get("dns_key", ""))
        if provider.lower() != target_provider.lower():
            log("⏭  %s provider=%s 与目标 Key 的 provider=%s 不一致，跳过"
                % (name, provider, target_provider))
            continue
        if current == key_name:
            log("⏭  %s 已登记 dns_key=%r，无需修改" % (name, current))
            continue
        if current and not force:
            log("⏭  %s 已有 dns_key=%r 且非目标值，默认不覆盖（如需覆盖加 --force）"
                % (name, current))
            continue
        cands = resolve_candidates(keys, provider)
        if len(cands) > 1 and not force:
            log("⚠️  %s provider=%s 存在多个候选 %s；将由 --key-name 显式指定为 %r"
                % (name, provider, cands, key_name))
        planned.append((mp, name, current, key_name))

    if not planned:
        log("✅ 无需修改")
        return 0

    log("\n将执行以下修改:")
    for mp, name, old, new in planned:
        log("  %-24s dns_key: %r → %r" % (name, old, new))

    if not apply:
        log("\n[dry-run] 未写盘。确认无误后加 --apply。")
        return 0

    bak = backup([certs_dir, os.path.join(os.path.dirname(certs_dir), "dns_keys.json")], "migrate")
    log("\n已备份到: %s" % bak)

    for mp, name, _old, new in planned:
        meta = load_json(mp)
        meta["dns_key"] = new
        atomic_write_json(mp, meta)
        log("  ✅ %s 已写入 dns_key=%r" % (name, new))

    log("\n完成，共修改 %d 个证书。请运行 --verify 复核。" % len(planned))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="为存量 ACME 证书登记 meta.dns_key")
    ap.add_argument("--certs-dir", required=True, help="data/certs 目录")
    ap.add_argument("--key-name", required=True, help="要登记的 DNS Key 名（dns_keys.json 中的键）")
    ap.add_argument("--dns-keys", default=None, help="dns_keys.json 路径（默认取 certs-dir 的父目录）")
    ap.add_argument("--apply", action="store_true", help="真正写盘（默认 dry-run）")
    ap.add_argument("--force", action="store_true", help="允许覆盖已有 dns_key / 绕过歧义告警")
    ap.add_argument("--verify", action="store_true", help="只校验，不修改")
    args = ap.parse_args()

    certs_dir = os.path.abspath(args.certs_dir)
    if not os.path.isdir(certs_dir):
        log("❌ --certs-dir 不存在: %s" % certs_dir)
        return 1
    keys_path = args.dns_keys or os.path.join(os.path.dirname(certs_dir), "dns_keys.json")
    if not os.path.isfile(keys_path):
        log("❌ dns_keys.json 不存在: %s" % keys_path)
        return 1
    keys = load_json(keys_path)

    if args.verify:
        rc = cmd_verify(certs_dir, keys)
        log("\n%s" % ("✅ 校验通过" if rc == 0 else "❌ 校验失败"))
        return rc
    return cmd_migrate(certs_dir, args.key_name, keys, args.apply, args.force)


if __name__ == "__main__":
    sys.exit(main())
