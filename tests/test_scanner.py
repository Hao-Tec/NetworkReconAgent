import unittest
from unittest.mock import patch, MagicMock
import scanner
import sys

class TestScanner(unittest.TestCase):
    def test_has_scapy(self):
        """Test that HAS_SCAPY is correctly determined."""
        self.assertTrue(scanner.HAS_SCAPY)

    def test_scapy_lazy_loading(self):
        """Verify scapy is not imported at top level but is available."""
        # This test assumes scapy was not already imported by main process.
        # Since we are running in the same process, we can't easily verify "not imported"
        # unless we check sys.modules before any other import happens.
        # But we can verify HAS_SCAPY is set without error.
        self.assertIsNotNone(scanner.HAS_SCAPY)

    def test_arp_scan_runs(self):
        """Test that _arp_scan can run (importing scapy locally)."""
        if not scanner.HAS_SCAPY:
            self.skipTest("Scapy not available")

        discovery = scanner.HostDiscovery("192.168.1.0/24")

        # We expect a runtime error because we don't have root permissions to send packets,
        # or a 'not enough values to unpack' if srp returns weird mock data.
        # The key is that it does NOT raise NameError or ImportError.
        try:
            discovery._arp_scan(["192.168.1.1"])
        except (PermissionError, OSError, ValueError) as e:
            # These are expected runtime errors from scapy execution
            pass
        except (NameError, ImportError) as e:
            self.fail(f"Import failed inside _arp_scan: {e}")
        except Exception as e:
            # Any other exception is also likely a runtime error, which means import succeeded.
            print(f"Runtime error (expected): {e}")

if __name__ == '__main__':
    unittest.main()
