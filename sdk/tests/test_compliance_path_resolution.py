"""Tests for compliance.py path-resolution + import-error behavior.

Locks the customer-onboarding contract: AIEGIS_COMPLIANCE_PATH env-var
behavior + fail-loud-vs-silent semantics. Composes with the README docs.

Run: python3 -m unittest tests.test_compliance_path_resolution
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


class TestComplianceePathResolution(unittest.TestCase):
    """Tests _resolve_compliance_path() — the import-time path-resolver."""

    def setUp(self) -> None:
        # Save + clear env so test cases control it explicitly.
        self._saved_env = os.environ.pop("AIEGIS_COMPLIANCE_PATH", None)
        # Force re-import to pick up clean env-var state. The module caches
        # _COMPLIANCE_PATH at import-time; we need fresh resolution per test.
        for mod in list(sys.modules):
            if mod.startswith("aiegis_agent.compliance") or mod == "generator":
                del sys.modules[mod]

    def tearDown(self) -> None:
        if self._saved_env is not None:
            os.environ["AIEGIS_COMPLIANCE_PATH"] = self._saved_env

    def test_env_unset_falls_back_to_dev_path_if_exists(self):
        """When env unset, falls back to /Users/velo/... dev path if present."""
        from aiegis_agent.compliance import _resolve_compliance_path
        result = _resolve_compliance_path()
        # On this dev machine the fallback exists; on customer machines it won't
        if Path("/Users/velo/Documents/VELO/aiegis-compliance-bundle").exists():
            self.assertEqual(result, Path("/Users/velo/Documents/VELO/aiegis-compliance-bundle"))
        else:
            self.assertIsNone(result)

    def test_env_set_to_existing_directory_resolves(self):
        """When env points at a real dir, returns it directly."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["AIEGIS_COMPLIANCE_PATH"] = tmp
            from aiegis_agent.compliance import _resolve_compliance_path
            self.assertEqual(_resolve_compliance_path(), Path(tmp))

    def test_env_set_to_nonexistent_raises_loud(self):
        """Loud-fail rationale: silent downgrade to dev path would mask
        customer mis-config (env-set typo). The raise happens at
        module-import time because _resolve_compliance_path() is called
        from module top-level — that's the intentional contract."""
        os.environ["AIEGIS_COMPLIANCE_PATH"] = "/does/not/exist/aiegis"
        with self.assertRaises(ImportError) as ctx:
            import aiegis_agent.compliance  # noqa: F401  triggers module top-level
        self.assertIn("AIEGIS_COMPLIANCE_PATH", str(ctx.exception))
        self.assertIn("/does/not/exist/aiegis", str(ctx.exception))

    def test_env_set_to_empty_string_treated_as_unset(self):
        """Empty env-var is equivalent to unset (consistent with shell semantics)."""
        os.environ["AIEGIS_COMPLIANCE_PATH"] = ""
        from aiegis_agent.compliance import _resolve_compliance_path
        # Empty falls through to dev path fallback (or None)
        result = _resolve_compliance_path()
        # If dev fallback exists, returns it; otherwise None — both valid for empty
        self.assertTrue(result is None or result.exists())

    def test_build_compliance_bundle_import_error_names_env_var(self):
        """When HAS_COMPLIANCE is False, the error message must guide the
        customer to AIEGIS_COMPLIANCE_PATH (first-5-min onboarding UX)."""
        # Force HAS_COMPLIANCE=False scenario by setting env to bad path
        # then monkey-patching _resolve_compliance_path to return None
        from aiegis_agent import compliance
        with patch.object(compliance, "HAS_COMPLIANCE", False), \
             patch.object(compliance, "_IMPORT_ERROR",
                          "aiegis-compliance-bundle package not found. "
                          "Set AIEGIS_COMPLIANCE_PATH=/path/to/aiegis-compliance-bundle"):
            # build_compliance_bundle should raise ImportError with the cached message
            agent_stub = type("A", (), {"name": "x", "did": "did:aiegis:operator:y"})()
            with self.assertRaises(ImportError) as ctx:
                compliance.build_compliance_bundle(
                    agent=agent_stub, events=[], customer_did="did:aiegis:customer:z",
                    valid_from=None, valid_until=None, policy_bundle={},
                )
            self.assertIn("AIEGIS_COMPLIANCE_PATH", str(ctx.exception))


class TestDoctorExitCodeContract(unittest.TestCase):
    """Lock the CI fail-loud contract: doctor must exit 1 on broken env.

    Per Nel regression-catch 2026-05-10 22:53: moving doctor from
    `python -m aiegis_agent.compliance` to `python -m aiegis_agent doctor`
    initially broke this because __init__.py eagerly imported compliance,
    so the ImportError fired BEFORE main() could catch it. Lazy-import
    via PEP 562 __getattr__ restored the contract. This test prevents the
    regression: any future change that re-eager-imports compliance OR
    fails to convert ImportError into exit 1 will fail this test."""

    def setUp(self) -> None:
        self._saved_env = os.environ.pop("AIEGIS_COMPLIANCE_PATH", None)

    def tearDown(self) -> None:
        if self._saved_env is not None:
            os.environ["AIEGIS_COMPLIANCE_PATH"] = self._saved_env

    def test_doctor_exits_1_on_nonexistent_env_path(self):
        import subprocess
        env = os.environ.copy()
        env["AIEGIS_COMPLIANCE_PATH"] = "/aiegis/should/never/exist"
        proc = subprocess.run(
            [sys.executable, "-m", "aiegis_agent", "doctor"],
            env=env, capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        self.assertEqual(proc.returncode, 1,
            f"doctor must exit 1 on broken env (got {proc.returncode}; stderr: {proc.stderr})")
        self.assertIn("AIEGIS_COMPLIANCE_PATH", proc.stderr)

    def test_package_import_does_not_crash_on_broken_env(self):
        """Lazy-import: `import aiegis_agent` must NOT raise even when env is
        broken, because unrelated subcommands (create/list/sign) need to work.
        Only access to compliance-related attrs should raise."""
        import subprocess
        env = os.environ.copy()
        env["AIEGIS_COMPLIANCE_PATH"] = "/aiegis/should/never/exist"
        proc = subprocess.run(
            [sys.executable, "-c", "import aiegis_agent; print(aiegis_agent.__version__)"],
            env=env, capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        self.assertEqual(proc.returncode, 0,
            f"import aiegis_agent must succeed on broken env (got {proc.returncode}; stderr: {proc.stderr})")
        self.assertIn("0.6", proc.stdout)


if __name__ == "__main__":
    unittest.main()
