import unittest
from unittest.mock import patch, MagicMock
import subprocess
import sys
import os

# Add parent directory to path so we can import scanner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import MacScanner

class TestMacScanner(unittest.TestCase):

    def test_mac_scanner_integration(self):
        """Test that MacScanner works with real arp command (if available)."""
        # This tests that the code logic doesn't crash on valid input
        # and that the regex logic is at least functional on the current platform.
        try:
            subprocess.check_output(["arp", "-a"])
            has_arp = True
        except (OSError, subprocess.CalledProcessError):
            has_arp = False

        if has_arp:
            scanner = MacScanner()
            # We can't guarantee entries in a test container, but we can verify no crash
            self.assertIsInstance(scanner.arp_cache, dict)

    @patch('subprocess.check_output')
    def test_no_shell_true(self, mock_check_output):
        """Verify that subprocess.check_output is NOT called with shell=True."""
        # Mock the output so _refresh_arp doesn't fail
        mock_check_output.return_value = b"? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"

        scanner = MacScanner()

        # Verify call args
        # We expect call(["arp", "-a"], shell=True) -> BEFORE FIX
        # We expect call(["arp", "-a"]) -> AFTER FIX

        # Check all calls
        for call in mock_check_output.call_args_list:
            args, kwargs = call
            # Check if shell=True is passed
            if kwargs.get('shell') is True:
                 self.fail("subprocess.check_output called with shell=True! Security risk.")

            # Check if command is a list
            cmd = args[0]
            if isinstance(cmd, str) and not kwargs.get('shell'):
                 # It's okay to pass string if shell=False, but usually we want list for args
                 # However, "arp -a" as string without shell=True fails if it has arguments
                 # and we are not using shell? No, check_output("arp -a") searches for executable named "arp -a".
                 # So it MUST be a list if it has arguments and shell=False.
                 pass

            if isinstance(cmd, list):
                 self.assertEqual(cmd, ["arp", "-a"])

if __name__ == '__main__':
    unittest.main()
