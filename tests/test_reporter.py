import unittest
import csv
import os
import json
from reporter import _sanitize_csv_cell, save_report

class TestReporter(unittest.TestCase):
    def test_sanitize_csv_cell(self):
        # Test dangerous characters
        self.assertEqual(_sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(_sanitize_csv_cell("+1+1"), "'+1+1")
        self.assertEqual(_sanitize_csv_cell("-1+1"), "'-1+1")
        self.assertEqual(_sanitize_csv_cell("@1+1"), "'@1+1")

        # Test safe strings
        self.assertEqual(_sanitize_csv_cell("Safe"), "Safe")
        self.assertEqual(_sanitize_csv_cell("123"), "123")

        # Test non-string types
        self.assertEqual(_sanitize_csv_cell(123), 123)
        self.assertEqual(_sanitize_csv_cell(None), None)

    def test_save_report_csv_injection(self):
        filename = "test_injection.csv"
        data = {
            "hosts": [
                {
                    "ip": "127.0.0.1",
                    "mac": "00:00:00:00:00:00",
                    "services": [
                        {
                            "port": 80,
                            "url": "http://127.0.0.1",
                            "status": 200,
                            "fingerprint": "=cmd|' /C calc'!A0"
                        }
                    ]
                }
            ]
        }

        try:
            save_report(data, filename)

            with open(filename, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                row = next(reader)
                self.assertEqual(row["fingerprint"], "'=cmd|' /C calc'!A0")

        finally:
            if os.path.exists(filename):
                os.remove(filename)

if __name__ == '__main__':
    unittest.main()
