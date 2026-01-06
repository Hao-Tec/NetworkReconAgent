import unittest
from unittest.mock import MagicMock, patch
from scanner import BannerGrabber, _clean_text

class TestScannerSecurity(unittest.TestCase):

    def test_clean_text_strips_ansi(self):
        """Test that _clean_text correctly removes ANSI escape codes."""
        text = "\x1b[31mRed\x1b[0m Text"
        cleaned = _clean_text(text)
        self.assertEqual(cleaned, "Red Text")

    def test_clean_text_complex_ansi(self):
        """Test more complex ANSI codes."""
        text = "\x1b[1;31;40mBoldRedOnBlack\x1b[0m"
        cleaned = _clean_text(text)
        self.assertEqual(cleaned, "BoldRedOnBlack")

    def test_clean_text_cursor_movement(self):
        """Test ANSI cursor movement codes."""
        # move up, move down
        text = "Line1\x1b[1AOverwritten"
        # The regex should strip \x1b[1A
        cleaned = _clean_text(text)
        self.assertEqual(cleaned, "Line1Overwritten")

    @patch('socket.socket')
    def test_banner_sanitization(self, mock_socket):
        """Test that BannerGrabber sanitizes output."""
        # Setup mock
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance

        # ANSI Red color code + "Malicious" + Reset code
        malicious_banner = b"\x1b[31mMalicious\x1b[0m"
        mock_instance.recv.return_value = malicious_banner

        # Test generic banner grab (port 80)
        result = BannerGrabber.grab_banner("127.0.0.1", 80)
        self.assertEqual(result, "Malicious")
        self.assertNotIn("\x1b", result)

    @patch('socket.socket')
    def test_ssh_banner_sanitization(self, mock_socket):
        """Test SSH specific path sanitization."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance

        # SSH banner with ANSI
        malicious_banner = b"SSH-2.0-OpenSSH_8.2p1 \x1b[31m(Evil)\x1b[0m"
        mock_instance.recv.return_value = malicious_banner

        result = BannerGrabber.grab_banner("127.0.0.1", 22)
        # Expected format: "SSH: <banner>"
        self.assertEqual(result, "SSH: SSH-2.0-OpenSSH_8.2p1 (Evil)")
        self.assertNotIn("\x1b", result)

if __name__ == '__main__':
    unittest.main()
