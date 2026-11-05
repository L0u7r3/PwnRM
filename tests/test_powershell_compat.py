"""Regression checks for Windows PowerShell 5.1 payload compatibility."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.adcs import ADCSModule
from pwnrm.modules.lateral import LateralModule


def _render(module):
    shell = MagicMock()
    shell.write_line = MagicMock()
    module.run(shell, [])
    command = shell.run_with_interrupt.call_args[0][0]
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return base64.b64decode(encoded).decode("utf-16le")


class TestWindowsPowerShellCompatibility(unittest.TestCase):
    def test_adcs_avoids_powershell_7_null_coalescing(self):
        script = _render(ADCSModule())
        self.assertNotIn("??", script)
        self.assertIn("$null -eq $acceptTrusted", script)

    def test_lateral_delimits_scheme_variable_before_colon(self):
        script = _render(LateralModule())
        self.assertIn('"${scheme}://$t`:$p/wsman"', script)
        self.assertNotIn('"$scheme://', script)


if __name__ == "__main__":
    unittest.main()
