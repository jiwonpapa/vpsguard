#!/usr/bin/env python3
"""DET-013: fetch, validate, and atomically pin official crawler CIDR feeds."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import tempfile
import urllib.request
from typing import Any

SOURCES = {
    "google": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "bing": "https://www.bing.com/toolbox/bingbot.json",
    "naver": "https://searchadvisor.naver.com/doc/naverbot.json",
}


def normalize(feeds: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Convert official provider JSON into the stable VPSGuard pin contract."""
    networks: list[dict[str, Any]] = []
    generated: list[str] = []
    for provider, feed in feeds.items():
        creation_time = feed.get("creationTime")
        prefixes = feed.get("prefixes")
        if not isinstance(creation_time, str) or not isinstance(prefixes, list):
            raise ValueError(f"{provider}: invalid feed schema")
        cidrs: list[str] = []
        for prefix in prefixes:
            if not isinstance(prefix, dict):
                raise ValueError(f"{provider}: invalid prefix row")
            value = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            if not isinstance(value, str):
                raise ValueError(f"{provider}: missing prefix")
            cidrs.append(str(ipaddress.ip_network(value, strict=True)))
        if not cidrs:
            raise ValueError(f"{provider}: empty feed")
        networks.append({"provider": provider, "cidrs": sorted(set(cidrs))})
        generated.append(creation_time)
    return {
        "schema_version": 1,
        "generated_at": max(generated),
        "sources": SOURCES,
        "networks": networks,
    }


def fetch(url: str) -> dict[str, Any]:
    """Fetch one bounded HTTPS JSON document."""
    request = urllib.request.Request(url, headers={"User-Agent": "VPSGuard-crawler-feed/1"})
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}: {url}")
        payload = response.read(2 * 1024 * 1024 + 1)
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError(f"feed too large: {url}")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"root is not object: {url}")
    return value


def write_atomic(path: pathlib.Path, value: dict[str, Any]) -> None:
    """Write a complete deterministic file before replacing the active pin."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    feeds = {provider: fetch(url) for provider, url in SOURCES.items()}
    write_atomic(args.output, normalize(feeds))
    print(f"crawler network pin: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
