"""Regression tests for the repository's AST security auditors."""

import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_auditor(name: str):
    path = ROOT / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestAuditScripts(unittest.TestCase):
    def test_network_audit_does_not_misread_false_default_as_verify_false(self):
        module = load_auditor("audit_network")
        source = (
            "def configure(transport, args):\n"
            "    transport.session.verify = not bool(getattr(args, 'no_ssl_verify', False))\n"
        )
        visitor = module.NetworkAuditVisitor("src/pwnrm/core/api.py", source)
        visitor.visit(ast.parse(source))
        self.assertEqual(visitor.findings, [])

    def test_network_audit_still_reports_literal_verify_false(self):
        module = load_auditor("audit_network")
        source = "session.verify = False\n"
        visitor = module.NetworkAuditVisitor("src/pwnrm/core/api.py", source)
        visitor.visit(ast.parse(source))
        self.assertEqual(len(visitor.findings), 1)
        self.assertEqual(visitor.findings[0]["severity"], "CRITICAL")

    def test_secret_audit_parses_multiline_history_regex(self):
        module = load_auditor("audit_secrets_exposure")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shell_dir = root / "src" / "pwnrm" / "shell"
            shell_dir.mkdir(parents=True)
            (shell_dir / "pwnshell.py").write_text(
                "import re\n"
                "HISTORY_EXCLUDE_PATTERN = re.compile(\n"
                "    r'(?:-p\\b|-H\\b|--hash\\b|--pfx-pass\\b|mimikatz|secretsdump|lsass|ccache|kirbi|dpapi)',\n"
                "    re.IGNORECASE,\n"
                ")\n",
                encoding="utf-8",
            )
            self.assertEqual(module.audit_history_exclude_regex(root), [])


if __name__ == "__main__":
    unittest.main()
