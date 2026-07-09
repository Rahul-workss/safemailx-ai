import base64
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from server.gmail_labels import apply_result_label, ensure_safemailx_label_ids
from server.gmail_watcher import enqueue_labeled_gmail_messages, enqueue_unread_forwarded_messages
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
    def __init__(self, labeled_ids=None, label_message_map=None) -> None:
        self.read_ids = []
        self.get_ids = []
        self.modify_calls = []
        self.labeled_ids = labeled_ids if labeled_ids is not None else ["msg-1"]
        # Map from label_id -> list of message ids (for _count_messages_with_label)
        self.label_message_map = label_message_map or {}
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
        label_ids = kwargs.get("labelIds") or []
        max_results = kwargs.get("maxResults")

        if label_ids:
            lid = label_ids[0]
            # Check label_message_map first (used for migration tests)
            if lid in self.label_message_map:
                msgs = self.label_message_map[lid]
                if max_results:
                    msgs = msgs[:max_results]
                return FakeExecute({
                    "messages": [{"id": m} for m in msgs],
                    "resultSizeEstimate": len(self.label_message_map[lid]),
                })
            # Default behavior for scan labels
            if lid in {"lbl-scan", "created-0"}:
                return FakeExecute({"messages": [{"id": msg_id} for msg_id in self.labeled_ids],
                                    "resultSizeEstimate": len(self.labeled_ids)})
            # Unknown label ID (unless UNREAD) — return empty
            if lid != "UNREAD":
                return FakeExecute({"messages": [], "resultSizeEstimate": 0})
                
        return FakeExecute({"messages": [{"id": "msg-1"}, {"id": "msg-2"}],
                            "resultSizeEstimate": 2})

    def get(self, **kwargs):
        self.get_ids.append(kwargs["id"])
        return FakeExecute(self.messages[kwargs["id"]])

    def modify(self, **kwargs):
        body = kwargs.get("body", {})
        self.modify_calls.append({"id": kwargs["id"], "body": body})
        if body.get("removeLabelIds") == ["UNREAD"]:
            self.read_ids.append(kwargs["id"])
        return FakeExecute({})


class FakeGmailLabels:
    def __init__(self, existing=None) -> None:
        self.labels = existing if existing is not None else [
            {"id": "lbl-scan", "name": "SafeMail X Scan"},
            {"id": "lbl-queued", "name": "SafeMail X Queued"},
            {"id": "lbl-safe", "name": "SafeMail X Safe"},
            {"id": "lbl-suspicious", "name": "SafeMail X Suspicious"},
            {"id": "lbl-phishing", "name": "SafeMail X Phishing"},
            {"id": "lbl-failed", "name": "SafeMail X Failed"},
        ]
        self.created = []
        self.deleted = []

    def list(self, **kwargs):
        return FakeExecute({"labels": list(self.labels)})

    def create(self, **kwargs):
        name = kwargs["body"]["name"]
        label = {"id": f"created-{len(self.created)}", "name": name}
        self.created.append(label)
        self.labels.append(label)
        return FakeExecute(label)

    def patch(self, **kwargs):
        label_id = kwargs["id"]
        new_name = kwargs["body"]["name"]
        for label in self.labels:
            if label["id"] == label_id:
                label["name"] = new_name
                return FakeExecute(label)
        return FakeExecute({})

    def delete(self, **kwargs):
        label_id = kwargs["id"]
        self.deleted.append(label_id)
        self.labels = [l for l in self.labels if l["id"] != label_id]
        return FakeExecute({})


class FakeGmailUsers:
    def __init__(self, labeled_ids=None, labels=None, label_message_map=None) -> None:
        self._messages = FakeGmailMessages(labeled_ids=labeled_ids, label_message_map=label_message_map)
        self._labels = FakeGmailLabels(existing=labels)

    def messages(self):
        return self._messages

    def labels(self):
        return self._labels


class FakeGmailService:
    def __init__(self, labeled_ids=None, labels=None, label_message_map=None) -> None:
        self._users = FakeGmailUsers(labeled_ids=labeled_ids, labels=labels, label_message_map=label_message_map)

    def users(self):
        return self._users


class GmailWatcherTests(unittest.TestCase):
    def test_legacy_forwarded_messages_still_queue_forwarded_mail_only(self):
        service = FakeGmailService()
        queue = FakeQueue()

        enqueued = enqueue_unread_forwarded_messages(
            service=service,
            repository=ScanRepository(),
            scan_queue=queue,
        )

        self.assertEqual(enqueued, 1)
        self.assertEqual(len(queue.jobs), 1)
        self.assertEqual(queue.jobs[0]["source"], "web_forwarding")
        self.assertEqual(queue.jobs[0]["type"], "manual_text")
        self.assertIn("verify your password", queue.jobs[0]["body"])
        self.assertEqual(
            service.users().messages().read_ids,
            ["msg-1", "msg-2"],
        )

    def test_label_scan_does_not_fetch_unlabeled_messages(self):
        service = FakeGmailService(labeled_ids=[])
        queue = FakeQueue()

        enqueued = enqueue_labeled_gmail_messages(
            service=service,
            repository=ScanRepository(),
            scan_queue=queue,
        )

        self.assertEqual(enqueued, 0)
        self.assertEqual(queue.jobs, [])
        self.assertEqual(service.users().messages().get_ids, [])
        self.assertEqual(service.users().messages().read_ids, [])

    def test_label_scan_queues_only_labeled_message_without_fetching_body(self):
        service = FakeGmailService(labeled_ids=["msg-1"])
        queue = FakeQueue()

        enqueued = enqueue_labeled_gmail_messages(
            service=service,
            repository=ScanRepository(),
            scan_queue=queue,
            user_id="user-1",
        )

        self.assertEqual(enqueued, 1)
        self.assertEqual(queue.jobs[0]["type"], "gmail_label_message")
        self.assertEqual(queue.jobs[0]["source"], "gmail_label_app")
        self.assertEqual(queue.jobs[0]["gmail_message_id"], "msg-1")
        self.assertEqual(queue.jobs[0]["user_id"], "user-1")
        self.assertEqual(service.users().messages().get_ids, [])
        self.assertEqual(
            service.users().messages().modify_calls[-1],
            {
                "id": "msg-1",
                "body": {
                    "removeLabelIds": ["lbl-scan"],
                    "addLabelIds": ["lbl-queued"],
                },
            },
        )

    def test_missing_safemailx_labels_are_created(self):
        service = FakeGmailService(labels=[])

        label_ids = ensure_safemailx_label_ids(service)

        self.assertEqual(set(label_ids.keys()), {"scan", "queued", "safe", "suspicious", "phishing", "failed"})
        self.assertEqual(len(service.users().labels().created), 6)

    def test_result_label_replaces_queued_label(self):
        service = FakeGmailService()
        label_ids = ensure_safemailx_label_ids(service)

        apply_result_label(service, "msg-1", "phishing", label_ids)

        self.assertEqual(
            service.users().messages().modify_calls[-1],
            {
                "id": "msg-1",
                "body": {
                    "removeLabelIds": ["lbl-queued"],
                    "addLabelIds": ["lbl-phishing"],
                },
            },
        )

    def test_old_trustmail_labels_are_renamed(self):
        old_labels = [
            {"id": "lbl-scan", "name": "TrustMail Scan"},
            {"id": "lbl-queued", "name": "TrustMail Queued"},
            {"id": "lbl-safe", "name": "TrustMail Safe"},
            {"id": "lbl-suspicious", "name": "TrustMail Suspicious"},
            {"id": "lbl-phishing", "name": "TrustMail Phishing"},
            {"id": "lbl-failed", "name": "TrustMail Failed"},
        ]
        service = FakeGmailService(labels=old_labels)

        label_ids = ensure_safemailx_label_ids(service)

        # Verify that all label IDs are resolved and match the original IDs
        self.assertEqual(label_ids["scan"], "lbl-scan")
        self.assertEqual(label_ids["queued"], "lbl-queued")
        self.assertEqual(label_ids["safe"], "lbl-safe")
        self.assertEqual(label_ids["suspicious"], "lbl-suspicious")
        self.assertEqual(label_ids["phishing"], "lbl-phishing")
        self.assertEqual(label_ids["failed"], "lbl-failed")

        # Verify that their display names are updated in the service labels list
        updated_names = {l["id"]: l["name"] for l in service.users().labels().labels}
        self.assertEqual(updated_names["lbl-scan"], "SafeMail X Scan")
        self.assertEqual(updated_names["lbl-queued"], "SafeMail X Queued")
        self.assertEqual(updated_names["lbl-safe"], "SafeMail X Safe")
        self.assertEqual(updated_names["lbl-suspicious"], "SafeMail X Suspicious")
        self.assertEqual(updated_names["lbl-phishing"], "SafeMail X Phishing")
        self.assertEqual(updated_names["lbl-failed"], "SafeMail X Failed")

    def test_dual_labels_old_has_messages_new_empty_uses_old(self):
        """When BOTH TrustMail and SafeMail X labels exist,
        and the old one has messages but new one is empty,
        the old label should be used (new deleted, old renamed)."""
        both_labels = [
            {"id": "old-scan", "name": "TrustMail Scan"},
            {"id": "new-scan", "name": "SafeMail X Scan"},
            {"id": "old-queued", "name": "TrustMail Queued"},
            {"id": "new-queued", "name": "SafeMail X Queued"},
            {"id": "old-safe", "name": "TrustMail Safe"},
            {"id": "new-safe", "name": "SafeMail X Safe"},
            {"id": "old-suspicious", "name": "TrustMail Suspicious"},
            {"id": "new-suspicious", "name": "SafeMail X Suspicious"},
            {"id": "old-phishing", "name": "TrustMail Phishing"},
            {"id": "new-phishing", "name": "SafeMail X Phishing"},
            {"id": "old-failed", "name": "TrustMail Failed"},
            {"id": "new-failed", "name": "SafeMail X Failed"},
        ]
        # Old scan label has messages, new scan label is empty
        label_message_map = {
            "old-scan": ["msg-1"],
            "new-scan": [],
        }
        service = FakeGmailService(
            labels=both_labels,
            label_message_map=label_message_map,
        )

        label_ids = ensure_safemailx_label_ids(service)

        # The scan label should use the OLD label's ID (renamed)
        self.assertEqual(label_ids["scan"], "old-scan")

        # The empty new-scan label should have been deleted
        self.assertIn("new-scan", service.users().labels().deleted)

        # The old label should now be named "SafeMail X Scan"
        remaining = {l["id"]: l["name"] for l in service.users().labels().labels}
        self.assertEqual(remaining["old-scan"], "SafeMail X Scan")
        self.assertNotIn("new-scan", remaining)


if __name__ == "__main__":
    unittest.main()
