from typing import Any

import requests

from server.settings import EXPO_ACCESS_TOKEN


EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


def send_push_notifications(tokens: list[str], *, title: str, body: str, data: dict[str, Any]) -> None:
    if not tokens:
        return

    headers = {"Content-Type": "application/json"}
    if EXPO_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {EXPO_ACCESS_TOKEN}"

    messages = [
        {
            "to": token,
            "sound": "default",
            "title": title,
            "body": body,
            "data": data,
        }
        for token in tokens
    ]
    try:
        response = requests.post(EXPO_PUSH_URL, headers=headers, json=messages, timeout=5)
        if response.status_code >= 400:
            print(f"[PUSH] Expo push failed: {response.status_code} {response.text[:200]}")
    except Exception as exc:
        print(f"[PUSH] Expo push error: {exc}")
