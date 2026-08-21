#!/usr/bin/env python3
"""Dependency-free policy linter for the Jeeb reusable workflow."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class PolicyFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyFailure(message)


def job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines()
    try:
        jobs_index = next(index for index, line in enumerate(lines) if line == "jobs:")
    except StopIteration as exc:
        raise PolicyFailure("workflow has no jobs section") from exc
    starts: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        match = re.fullmatch(r"  ([a-z][a-z0-9_]*):", lines[index])
        if match:
            starts.append((match.group(1), index))
    require(bool(starts), "workflow has no jobs")
    blocks: dict[str, str] = {}
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        blocks[name] = "\n".join(lines[start:end])
    return blocks


def direct_value(block: str, key: str) -> str | None:
    match = re.search(rf"^    {re.escape(key)}:[ \t]*(.*?)[ \t]*$", block, re.MULTILINE)
    return match.group(1) if match else None


def permissions(block: str) -> dict[str, str]:
    inline = direct_value(block, "permissions")
    if inline == "{}":
        return {}
    require(inline == "", "job permissions must be an explicit mapping or {}")
    result: dict[str, str] = {}
    lines = block.splitlines()
    start = next(index for index, line in enumerate(lines) if line == "    permissions:")
    for line in lines[start + 1 :]:
        if len(line) - len(line.lstrip()) <= 4:
            break
        match = re.fullmatch(r"      ([a-z-]+):\s*(read|write|none)", line)
        require(match is not None, f"invalid permission line: {line.strip()}")
        result[match.group(1)] = match.group(2)
    return result


def dependencies(block: str) -> set[str]:
    value = direct_value(block, "needs")
    if value is None:
        return set()
    if value.startswith("[") and value.endswith("]"):
        return {item.strip() for item in value[1:-1].split(",") if item.strip()}
    return {value}


def lint(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    blocks = job_blocks(text)
    expected_jobs = {
        "contract_gate",
        "manager_capability",
        "source_preflight",
        "health_probe",
        "resolve_source",
        "test_build",
        "push_image",
        "finalize_deployment_lock",
        "assemble_runtime",
        "lease_orchestrator",
        "abort_preactive_lease",
    }
    require(set(blocks) == expected_jobs, "workflow job set changed without a policy update")

    forbidden = {
        "secrets: inherit": "secret inheritance is prohibited",
        "sshpass": "password SSH is prohibited",
        "StrictHostKeyChecking=no": "disabled SSH host checking is prohibited",
        "StrictHostKeyChecking=accept-new": "trust-on-first-use SSH is prohibited",
        "set -x": "shell tracing is prohibited",
        "docker login -p": "Docker passwords on argv are prohibited",
    }
    for marker, message in forbidden.items():
        require(marker not in text, message)

    for match in re.finditer(r"uses:\s*([^\s]+)", text):
        reference = match.group(1)
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", reference) is not None, f"action is not pinned by full SHA: {reference}")

    oidc_jobs = {name for name, block in blocks.items() if permissions(block).get("id-token") == "write"}
    require(
        oidc_jobs == {"manager_capability", "source_preflight", "resolve_source", "lease_orchestrator", "abort_preactive_lease"},
        "OIDC permission escaped the reviewed authentication/lifecycle jobs",
    )
    require(permissions(blocks["test_build"]) == {}, "untrusted test/build must have no GITHUB_TOKEN permissions")
    require(permissions(blocks["health_probe"]) == {}, "health probe fetch must have no GITHUB_TOKEN permissions")
    require(permissions(blocks["push_image"]) == {"packages": "write", "contents": "none"}, "push job permissions are not source-free and package-only")
    require("actions/checkout@" not in blocks["push_image"], "source-free push job may not check out a repository")
    require("source-" not in blocks["push_image"], "source-free push job may not download source artifacts")
    require("${{ secrets." not in "\n".join(line for line in text.splitlines() if line.startswith("          ") and not line.lstrip().startswith("JEEB_RUNTIME_SECRETS_JSON:")), "secrets may not be interpolated into shell commands")

    expected_dependencies = {
        "manager_capability": {"contract_gate"},
        "source_preflight": {"contract_gate", "manager_capability"},
        "health_probe": {"contract_gate", "manager_capability"},
        "resolve_source": {"contract_gate", "source_preflight"},
        "test_build": {"contract_gate", "resolve_source"},
        "push_image": {"contract_gate", "test_build"},
        "finalize_deployment_lock": {"contract_gate", "push_image"},
        "assemble_runtime": {"contract_gate", "finalize_deployment_lock", "health_probe"},
        "lease_orchestrator": {"contract_gate", "manager_capability", "assemble_runtime", "finalize_deployment_lock"},
        "abort_preactive_lease": {"contract_gate", "lease_orchestrator"},
    }
    for name, expected in expected_dependencies.items():
        require(dependencies(blocks[name]) == expected, f"job dependency mismatch for {name}")

    for name, block in blocks.items():
        if name not in {"contract_gate", "manager_capability"}:
            condition = direct_value(block, "if") or ""
            require("inputs.operation == 'deploy'" in condition, f"{name} is not excluded from capability-only mode")
    capability = blocks["manager_capability"]
    for prohibited in ("/leases", "source_broker.py", "docker", "packages: write"):
        require(prohibited not in capability, f"capability-only job contains resource operation: {prohibited}")
    require("manager_client.py capabilities" in capability, "capability job does not use the exact capability client path")
    require("environment: ${{ inputs.environment }}" in capability, "capability job is not bound to the protected environment")
    require("expected-job-workflow-sha" in capability and "expected-job-workflow-ref" in capability, "capability job does not assert exact workflow identity")

    require("finalize-lock" in blocks["finalize_deployment_lock"], "final deployment lock is not frozen from push receipts")
    require(
        "final-deployment-lock-" in blocks["lease_orchestrator"] and "--final-lock final-lock" in blocks["lease_orchestrator"],
        "lease job does not consume the finalized lock artifact",
    )
    require("build-intent" not in blocks["lease_orchestrator"], "lease job may not deploy directly from pre-build intent")
    require("health-probe" in blocks["assemble_runtime"], "runtime bundle omits the pinned health probe")
    require("if: ${{ always()" in blocks["abort_preactive_lease"], "abort guard is not state-aware always() work")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    args = parser.parse_args()
    try:
        lint(args.workflow)
        print("workflow policy: ok")
        return 0
    except (OSError, PolicyFailure) as exc:
        print(f"workflow policy failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
