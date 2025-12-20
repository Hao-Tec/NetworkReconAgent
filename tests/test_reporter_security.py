import unittest
import csv
import os
import json
from reporter import save_report

class TestReporterSecurity(unittest.TestCase):
    def test_csv_injection(self):
        """Test that malicious input is sanitized to prevent CSV injection"""
        malicious_input = "=cmd|' /C calc'!A0"
        data = {
            "hosts": [
                {
                    "ip": "1.2.3.4",
                    "mac": "00:00:00:00:00:00",
                    "services": [
                        {
                            "port": 80,
                            "url": "http://1.2.3.4",
                            "status": 200,
                            "fingerprint": malicious_input
                        }
                    ]
                }
            ]
        }

        filename = "test_vuln.csv"
        save_report(data, filename)

        with open(filename, "r") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            # Expecting single quote prepended
            self.assertEqual(row["fingerprint"], "'" + malicious_input)

        os.remove(filename)

if __name__ == '__main__':
    unittest.main()
