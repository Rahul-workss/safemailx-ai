from contextlib import contextmanager

import pytest

from server.outlook_graph import initialize_inbox_delta_cursor
from server.repository import ScanRepository


class _RecordingConnection:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))


@pytest.mark.parametrize("method,args", [
    ("set_gmail_protection", ("user-1", True, "gmail-history")),
    ("set_outlook_protection", ("user-1", True, "https://graph.microsoft.com/v1.0/delta")),
])
def test_postgres_auto_protection_preferences_bind_integer_values(method, args):
    repo = object.__new__(ScanRepository)
    repo.is_postgres = True
    connection = _RecordingConnection()

    @contextmanager
    def fake_db():
        yield connection

    repo._db = fake_db
    getattr(repo, method)(*args)

    assert connection.calls[0][1][0] == 1
    assert type(connection.calls[0][1][0]) is int


def test_outlook_delta_cursor_follows_pages_and_uses_recent_mail_filter():
    class FakeGraphClient:
        def __init__(self):
            self.urls = []

        def get(self, url):
            self.urls.append(url)
            if len(self.urls) == 1:
                return {"id": "inbox-id"}
            if len(self.urls) == 2:
                return {
                    "value": [],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$skiptoken=page2",
                }
            return {
                "value": [],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=cursor",
            }

    client = FakeGraphClient()
    cursor = initialize_inbox_delta_cursor(client)

    assert cursor.endswith("$deltatoken=cursor")
    assert len(client.urls) == 3
    assert "receivedDateTime%20ge%20" in client.urls[1]
    assert "$select=id,receivedDateTime" in client.urls[1]
    assert "$deltatoken=latest" not in client.urls[1]


def test_outlook_delta_cursor_rejects_untrusted_continuation_url():
    class FakeGraphClient:
        def __init__(self):
            self.calls = 0

        def get(self, url):
            self.calls += 1
            if self.calls == 1:
                return {"id": "inbox-id"}
            return {"@odata.nextLink": "https://attacker.example/steal-token"}

    with pytest.raises(RuntimeError, match="untrusted continuation"):
        initialize_inbox_delta_cursor(FakeGraphClient())
