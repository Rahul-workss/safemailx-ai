import base64
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from utils.email_parser import parse_email


def _gmail_b64(text):
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


class EmailParserTests(unittest.TestCase):
    def test_html_parser_removes_preheader_and_collects_images(self):
        html = """
        <html>
          <body>
            <div class="preheader" style="display:none;max-height:0">hidden preview junk</div>
            <p>Security Scan Report</p>
            <img src="https://example.test/report.png" />
          </body>
        </html>
        """
        message = {
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Fwd: report"},
                    {"name": "From", "value": "Rahul <rahul@example.test>"},
                ],
                "mimeType": "text/html",
                "body": {"data": _gmail_b64(html)},
            }
        }

        parsed = parse_email(service=None, message_id="msg-1", message=message)

        self.assertIn("Security Scan Report", parsed["body"])
        self.assertNotIn("hidden preview junk", parsed["body"])
        self.assertEqual(parsed["images"], ["https://example.test/report.png"])


if __name__ == "__main__":
    unittest.main()
