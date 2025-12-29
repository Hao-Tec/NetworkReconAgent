import unittest
from scanner import _clean_text

class TestScannerSecurity(unittest.TestCase):
    def test_clean_text_basic(self):
        """Test basic text cleaning."""
        self.assertEqual(_clean_text("Hello World"), "Hello World")
        self.assertEqual(_clean_text("  trimmed  "), "trimmed")

    def test_clean_text_ansi_stripping(self):
        """Test removal of ANSI escape codes."""
        # Red text
        malicious = "\033[31mMalicious\033[0m"
        self.assertEqual(_clean_text(malicious), "Malicious")

        # Complex ANSI
        complex_ansi = "\x1b[1;31;42mComplex\x1b[0m"
        self.assertEqual(_clean_text(complex_ansi), "Complex")

    def test_clean_text_mixed(self):
        """Test mixed content."""
        mixed = "Normal \033[31mRed\033[0m Normal"
        self.assertEqual(_clean_text(mixed), "Normal Red Normal")

    def test_clean_text_empty(self):
        """Test empty and None inputs."""
        self.assertEqual(_clean_text(""), "")
        self.assertEqual(_clean_text(None), "")

if __name__ == '__main__':
    unittest.main()
