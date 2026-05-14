import base64
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from server.gmail_watcher import enqueue_unread_forwarded_messages
from server.repository import ScanRepository


def _gmail_body(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


class FakeQueue:
    def __init__(self) -> None:
        self.jobs = []

    def enqueue(self, job):
        self.jobs.append(job)
        return len(self.jobs)


class FakeExecute:
    def __init__(self, payload) -> None:
        self.payload = payload

    def execute(self):
        return self.payload


class FakeGmailMessages:
    def __init__(self) -> None:
        self.read_ids = []
        self.messages = {
            "msg-1": {
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": "Fwd: Suspicious login"},
                        {"name": "From", "value": "User <user@example.com>"},
                    ],
                    "mimeType": "text/plain",
                    "body": {
                        "data": _gmail_body(
                            "---------- Forwarded message ---------\n"
                            "From: attacker@example.net\n"
                            "Please verify your password immediately."
                        )
                    },
                }
            },
            "msg-2": {
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": "Normal newsletter"},
                        {"name": "From", "value": "News <news@example.com>"},
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": _gmail_body("Not a forwarded scan request.")},
                }
            },
        }

    def list(self, **kwargs):
        return FakeExecute({"messages": [{"id": "msg-1"}, {"id": "msg-2"}]})

    def get(self, **kwargs):
        return FakeExecute(self.messages[kwargs["id"]])

    def modify(self, **kwargs):
        self.read_ids.append(kwargs["id"])
        return FakeExecute({})


class FakeGmailUsers:
    def __init__(self) -> None:
        self._messages = FakeGmailMessages()

    def messages(self):
        return self._messages


class FakeGmailService:
    def __init__(self) -> None:
        self._users = FakeGmailUsers()

    def users(self):
        return self._users


class GmailWatcherTests(unittest.TestCase):
    def test_enqueue_unread_forwarded_messages_queues_forwarded_mail_only(self):
        service = FakeGmailService()
        queue = FakeQueue()

        enqueued = enqueue_unread_forwarded_messages(
            service=service,
            repository=ScanRepository(),
            scan_queue=queue,
        )

        self.assertEqual(enqueued, 1)
        self.assertEqual(len(queue.jobs), 1)
        self.assertEqual(queue.jobs[0]["source"], "gmail")
        self.assertEqual(queue.jobs[0]["type"], "manual_text")
        self.assertIn("verify your password", queue.jobs[0]["body"])
        self.assertEqual(
            service.users().messages().read_ids,
            ["msg-1", "msg-2"],
        )


if __name__ == "__main__":
    unittest.main()
