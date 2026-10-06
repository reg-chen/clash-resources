#!/usr/bin/env python3
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vpn_generator_core as core

WARP_API_URL = "https://api.cloudflareclient.com/v0a737/reg"


def generate_wg_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def register_warp(public_key: str, timeout: float = 15.0) -> dict:
    tos = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    payload = json.dumps({
        "key": public_key,
        "install_id": "",
        "warp_enabled": True,
        "tos": tos,
        "type": "Windows",
        "locale": "en_US",
    }).encode("utf-8")
    request = urllib.request.Request(
        WARP_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"WARP API HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"WARP API 連線失敗: {exc.reason}") from exc

    try:
        data = json.loads(body)
        peer = data["config"]["peers"][0]
        addresses = data["config"]["interface"]["addresses"]
        if not peer.get("public_key") or not peer.get("endpoint", {}).get("host") or not addresses.get("v4"):
            raise KeyError("missing required WARP configuration fields")
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"WARP API 回傳格式不完整: {body[:500]}") from exc
    return data


def split_endpoint(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        closing = value.rfind("]")
        if closing <= 0 or closing + 2 > len(value) or value[closing + 1] != ":":
            raise ValueError(f"無法解析 WARP endpoint: {value}")
        return value[1:closing], int(value[closing + 2:])
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port:
        raise ValueError(f"無法解析 WARP endpoint: {value}")
    return host, int(port)


def _address(value: str) -> str:
    return value.split("/", 1)[0].strip()


def build_provider_yaml(private_key: str, registration: dict) -> str:
    peer = registration["config"]["peers"][0]
    addresses = registration["config"]["interface"]["addresses"]
    server, port = split_endpoint(str(peer["endpoint"]["host"]))
    ipv4 = _address(str(addresses["v4"]))
    ipv6 = _address(str(addresses.get("v6", ""))) if addresses.get("v6") else ""

    lines = [
        "# GENERATED FILE — Cloudflare WARP WireGuard provider payload for Mihomo.",
        "# Contains a private key. Keep this file local; do not commit it.",
        "proxies:",
        f"  - name: {core.yaml_quote('WARP')}",
        "    type: wireguard",
        f"    server: {core.yaml_quote(server)}",
        f"    port: {port}",
        f"    ip: {core.yaml_quote(ipv4)}",
    ]
    if ipv6:
        lines.append(f"    ipv6: {core.yaml_quote(ipv6)}")
    lines.extend([
        f"    private-key: {core.yaml_quote(private_key)}",
        f"    public-key: {core.yaml_quote(str(peer['public_key']))}",
        "    allowed-ips:",
        "      - 0.0.0.0/0",
        "    persistent-keepalive: 25",
        "    udp: true",
        "    mtu: 1280",
        "",
    ])
    return "\n".join(lines)


def generate_warp(*, out_dir: Path, timeout: float = 15.0) -> Path:
    providers = out_dir / "providers"
    providers.mkdir(parents=True, exist_ok=True)
    target = providers / "warp.yaml"

    print("[INFO] 產生 WARP WireGuard keypair...")
    private_key, public_key = generate_wg_keypair()
    print("[INFO] 向 Cloudflare WARP API 註冊 public key...")
    registration = register_warp(public_key, timeout=timeout)

    payload = build_provider_yaml(private_key, registration)
    temporary = target.with_suffix(".yaml.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(target)

    account = registration.get("account") or {}
    device_id = registration.get("id")
    if device_id:
        print(f"[INFO] WARP Device ID: {device_id}")
    if account.get("ttl"):
        print(f"[INFO] WARP account TTL: {account['ttl']}")
    print(f"[WRITE] {target}")
    return target


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate a local Cloudflare WARP Mihomo provider.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(r"P:\Clash"),
        help=r"Mihomo root directory; writes providers\warp.yaml (default: P:\Clash)",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    generate_warp(out_dir=args.out_dir, timeout=args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
