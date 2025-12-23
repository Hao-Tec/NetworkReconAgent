
import unittest
from unittest.mock import MagicMock, patch
import sys
import ipaddress

# Mock modules if they are not available
try:
    import scapy
except ImportError:
    pass

from scanner import HostDiscovery, MacScanner, MAC_VENDORS

class TestHostDiscovery(unittest.TestCase):
    def test_scan_arp_skip_hosts_generation(self):
        # We want to ensure that if method is ARP, we don't crash and we don't need hosts list.
        # Since we can't easily mock ipaddress.IPv4Network.hosts to fail (it's a generator),
        # we can just verify the code path executes _arp_scan without errors.

        scanner = HostDiscovery("192.168.1.0/24")

        # Force method to ARP
        scanner.method = "ARP"

        # Mock _arp_scan
        scanner._arp_scan = MagicMock(return_value=["192.168.1.1"])

        result = scanner.scan()

        scanner._arp_scan.assert_called_once()
        self.assertEqual(result, ["192.168.1.1"])

    def test_scan_ping_generates_hosts(self):
        scanner = HostDiscovery("192.168.1.0/30") # Small subnet: .0, .1, .2, .3
        scanner.method = "Ping"

        scanner._ping_scan = MagicMock(return_value=["192.168.1.1"])

        result = scanner.scan()

        scanner._ping_scan.assert_called_once()
        # _ping_scan takes (hosts, max_workers, progress_callback)
        call_args = scanner._ping_scan.call_args
        hosts_arg = call_args[0][0]

        # For /30, hosts are typically .1 and .2 (if strict=False and using hosts())
        # network.hosts() excludes network and broadcast
        expected_hosts = ["192.168.1.1", "192.168.1.2"]
        self.assertEqual(sorted(hosts_arg), sorted(expected_hosts))

class TestMacScanner(unittest.TestCase):
    def test_mac_lookup(self):
        # Verify MAC_VENDORS is working
        self.assertIn("B8:27:EB", MAC_VENDORS)

        # Test the helper function (which we can't easily import if it's private, but it's used by MacScanner)
        # We can test MacScanner.get_mac_info if we populate cache manually

        scanner = MacScanner()
        scanner.arp_cache["1.2.3.4"] = "B8:27:EB:00:00:01"

        info = scanner.get_mac_info("1.2.3.4")
        self.assertIn("Raspberry Pi", info)
        self.assertIn("B8:27:EB:00:00:01", info)

if __name__ == '__main__':
    unittest.main()
