from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from workflow_policy import PolicyFailure, lint


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "deploy-jeeb-ephemeral.yml"


class WorkflowPolicyTests(unittest.TestCase):
    def test_production_workflow_satisfies_policy(self) -> None:
        lint(WORKFLOW)

    def test_unpinned_action_is_rejected(self) -> None:
        original = WORKFLOW.read_text(encoding="utf-8")
        mutated = original.replace(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/checkout@v4",
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.yml"
            path.write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(PolicyFailure, "not pinned"):
                lint(path)

    def test_capability_path_cannot_gain_a_resource_dependency(self) -> None:
        original = WORKFLOW.read_text(encoding="utf-8")
        mutated = original.replace("needs: contract_gate\n", "needs: [contract_gate, push_image]\n", 1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.yml"
            path.write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(PolicyFailure, "dependency mismatch"):
                lint(path)

    def test_password_ssh_is_rejected(self) -> None:
        original = WORKFLOW.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.yml"
            path.write_text(original + "\n# sshpass\n", encoding="utf-8")
            with self.assertRaisesRegex(PolicyFailure, "password SSH"):
                lint(path)

    def test_runtime_uses_mounted_probe_and_never_curl(self) -> None:
        runtime = (ROOT / "scripts" / "remote_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("curl", runtime.lower())
        self.assertIn("target=/run/olivium/bin/http-probe,mode=0555", runtime)
        self.assertIn('health["type"] == "http"', runtime)

    def test_control_plane_destinations_are_not_caller_inputs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("inputs.manager_url", workflow)
        self.assertNotIn("inputs.manager_audience", workflow)
        self.assertNotIn("inputs.source_broker_url", workflow)
        self.assertNotIn("inputs.source_broker_audience", workflow)
        self.assertIn("MANAGER_URL: https://ephemeral.fds-8.space", workflow)

    def test_full_deployment_remains_fail_closed(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('test "$OPERATION" = capability', workflow)


if __name__ == "__main__":
    unittest.main()
