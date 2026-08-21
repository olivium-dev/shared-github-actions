#!/usr/bin/env python3
"""Fetch and verify the reviewed static health probe without source credentials."""

from __future__ import annotations

import argparse
import json
import ssl
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

from common import ContractError, canonical_sha256, read_json, require, sha256_bytes, write_json
from contracts import validate_build_intent, validate_config


DOCKER_CONFIG_MAX_BYTES = 500_000
PT_INTERP = 3
PT_LOAD = 1
EM_X86_64 = 62


def validate_static_amd64_elf(payload: bytes) -> None:
    require(len(payload) >= 64, "health probe is too small to be an ELF64 binary")
    require(payload[:4] == b"\x7fELF", "health probe is not an ELF binary")
    require(payload[4] == 2 and payload[5] == 1, "health probe must be little-endian ELF64")
    machine = struct.unpack_from("<H", payload, 18)[0]
    require(machine == EM_X86_64, "health probe must target amd64")
    require(struct.unpack_from("<H", payload, 16)[0] in {2, 3}, "health probe must be an executable or PIE")
    require(struct.unpack_from("<I", payload, 20)[0] == 1, "health probe has an unsupported ELF version")
    program_offset = struct.unpack_from("<Q", payload, 32)[0]
    program_entry_size = struct.unpack_from("<H", payload, 54)[0]
    program_count = struct.unpack_from("<H", payload, 56)[0]
    require(program_entry_size >= 56, "health probe has an invalid ELF program-header size")
    require(1 <= program_count <= 256, "health probe has an invalid ELF program-header count")
    require(program_offset + program_entry_size * program_count <= len(payload), "health probe ELF program headers are truncated")
    load_segments = 0
    for index in range(program_count):
        entry_offset = program_offset + index * program_entry_size
        program_type = struct.unpack_from("<I", payload, entry_offset)[0]
        require(program_type != PT_INTERP, "health probe must be statically linked (PT_INTERP is present)")
        if program_type == PT_LOAD:
            load_segments += 1
    require(load_segments >= 1, "health probe has no loadable ELF segment")


def download_exact(url: str, maximum_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "olivium-health-probe-fetch/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            require(response.geturl() == url, "health probe URL redirected; update the reviewed lock instead")
            content_length = response.headers.get("Content-Length")
            if content_length:
                require(int(content_length) <= maximum_bytes, "health probe exceeds the Docker config size limit")
            payload = response.read(maximum_bytes + 1)
    except (urllib.error.URLError, ValueError) as exc:
        raise ContractError(f"health probe download failed: {exc}") from exc
    require(len(payload) <= maximum_bytes, "health probe exceeds the Docker config size limit")
    return payload


def command_fetch(args: argparse.Namespace) -> None:
    config = validate_config(read_json(args.contracts / "config.json"), args.expected_service_count)
    intent = validate_build_intent(read_json(args.contracts / "build-intent.json"), config)
    contract = intent["healthProbe"]
    require(contract["size"] <= DOCKER_CONFIG_MAX_BYTES, "health probe exceeds the Docker config size limit")
    payload = download_exact(contract["url"], DOCKER_CONFIG_MAX_BYTES)
    require(len(payload) == contract["size"], "health probe byte size does not match the reviewed lock")
    digest = sha256_bytes(payload)
    require(digest == contract["sha256"], "health probe SHA-256 does not match the reviewed lock")
    validate_static_amd64_elf(payload)

    args.output.mkdir(parents=True, exist_ok=True)
    binary = args.output / "olivium-http-probe"
    binary.write_bytes(payload)
    binary.chmod(0o555)
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "olivium-http-probe", "digest": {"sha256": digest}}],
        "predicateType": "https://olivium.dev/provenance/pinned-static-probe/v1",
        "predicate": {
            "sourceUrl": contract["url"],
            "size": len(payload),
            "architecture": "amd64",
            "staticElf": True,
            "dockerConfigCompatible": len(payload) <= DOCKER_CONFIG_MAX_BYTES,
            "buildIntentSha256": canonical_sha256(intent),
        },
    }
    write_json(args.output / "health-probe-provenance.json", provenance, 0o644)
    write_json(
        args.output / "health-probe.json",
        {
            "apiVersion": "olivium.dev/health-probe-artifact/v1",
            "sha256": digest,
            "size": len(payload),
            "mode": "0555",
            "provenanceSha256": canonical_sha256(provenance),
        },
        0o644,
    )
    print(json.dumps({"ok": True, "sha256": digest, "size": len(payload)}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fetch", nargs="?")
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-service-count", type=int, default=24)
    return parser


def main() -> int:
    try:
        command_fetch(build_parser().parse_args())
        return 0
    except (ContractError, OSError) as exc:
        print(f"health probe verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
