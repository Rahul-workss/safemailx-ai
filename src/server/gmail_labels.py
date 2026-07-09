from typing import Any


SAFEMAILX_LABELS = {
    "scan": "SafeMail X Scan",
    "queued": "SafeMail X Queued",
    "safe": "SafeMail X Safe",
    "suspicious": "SafeMail X Suspicious",
    "phishing": "SafeMail X Phishing",
    "failed": "SafeMail X Failed",
}

# Old label names from the pre-rename era
_OLD_LABEL_NAMES = {
    "scan": "TrustMail Scan",
    "queued": "TrustMail Queued",
    "safe": "TrustMail Safe",
    "suspicious": "TrustMail Suspicious",
    "phishing": "TrustMail Phishing",
    "failed": "TrustMail Failed",
}


RESULT_LABEL_BY_VERDICT = {
    "legitimate": "safe",
    "suspicious": "suspicious",
    "phishing": "phishing",
    "failed": "failed",
}


def _labels_resource(service: Any):
    return service.users().labels()


def list_gmail_labels(service: Any) -> list[dict[str, Any]]:
    payload = _labels_resource(service).list(userId="me").execute()
    return payload.get("labels", [])


def _count_messages_with_label(service: Any, label_id: str) -> int:
    """Return approximate message count for a label (0 if none/error)."""
    try:
        result = service.users().messages().list(
            userId="me", labelIds=[label_id], maxResults=1
        ).execute()
        return result.get("resultSizeEstimate", len(result.get("messages", [])))
    except Exception:
        return 0


def ensure_safemailx_labels(service: Any) -> dict[str, dict[str, str]]:
    labels_list = list_gmail_labels(service)

    # Build lookup: lowercase name -> label dict
    existing_by_name_lower: dict[str, dict] = {}
    for lbl in labels_list:
        n = lbl.get("name")
        if n:
            existing_by_name_lower[n.lower()] = lbl

    print(f"[GMAIL LABELS] Found {len(labels_list)} total Gmail labels")

    resolved: dict[str, dict[str, str]] = {}

    for key, new_name in SAFEMAILX_LABELS.items():
        old_name = _OLD_LABEL_NAMES[key]
        new_label = existing_by_name_lower.get(new_name.lower())
        old_label = existing_by_name_lower.get(old_name.lower())

        print(f"[GMAIL LABELS] key={key}: new='{new_name}' exists={new_label is not None}"
              f", old='{old_name}' exists={old_label is not None}")

        chosen = None

        if new_label and old_label:
            # BOTH exist. Check which one actually has messages (for "scan" key).
            # The old one likely has the user's emails; the new one was auto-created empty.
            # Strategy: use the old label (it has messages), delete the empty new one,
            # then rename the old one to the new name.
            if key == "scan":
                old_count = _count_messages_with_label(service, old_label["id"])
                new_count = _count_messages_with_label(service, new_label["id"])
                print(f"[GMAIL LABELS] BOTH labels exist for '{key}': "
                      f"old('{old_name}' id={old_label['id']}) has ~{old_count} msgs, "
                      f"new('{new_name}' id={new_label['id']}) has ~{new_count} msgs")

                if old_count > 0 and new_count == 0:
                    # Delete the empty new label and rename old one
                    try:
                        _labels_resource(service).delete(
                            userId="me", id=new_label["id"]
                        ).execute()
                        print(f"[GMAIL LABELS] Deleted empty new label '{new_name}' (ID: {new_label['id']})")
                    except Exception as exc:
                        print(f"[GMAIL LABELS] Failed to delete empty new label: {exc}")

                    try:
                        chosen = _labels_resource(service).patch(
                            userId="me",
                            id=old_label["id"],
                            body={"name": new_name},
                        ).execute()
                        print(f"[GMAIL LABELS] Renamed '{old_name}' -> '{new_name}' (ID: {old_label['id']})")
                    except Exception as exc:
                        print(f"[GMAIL LABELS] Failed to rename old label: {exc}")
                        chosen = old_label  # fall back to using old label as-is
                elif new_count > 0:
                    # New label has messages, use it
                    chosen = new_label
                else:
                    # Both empty or old empty – just use the new one
                    chosen = new_label
            else:
                # For non-scan keys, prefer new if it exists
                # But also try to clean up: delete old, keep new
                chosen = new_label
                try:
                    _labels_resource(service).delete(
                        userId="me", id=old_label["id"]
                    ).execute()
                    print(f"[GMAIL LABELS] Cleaned up old label '{old_name}' (ID: {old_label['id']})")
                except Exception:
                    pass  # not critical

        elif new_label:
            # Only new label exists — use it directly
            chosen = new_label

        elif old_label:
            # Only old label exists — rename it to the new name
            try:
                old_label_name = old_label["name"]
                chosen = _labels_resource(service).patch(
                    userId="me",
                    id=old_label["id"],
                    body={"name": new_name},
                ).execute()
                print(f"[GMAIL LABELS] Renamed '{old_label_name}' -> '{new_name}' (ID: {old_label['id']})")
            except Exception as exc:
                print(f"[GMAIL LABELS] Failed to rename '{old_label['name']}': {exc}")
                chosen = None

        if not chosen:
            # Neither exists or rename failed — create fresh
            chosen = _labels_resource(service).create(
                userId="me",
                body={
                    "name": new_name,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                },
            ).execute()
            print(f"[GMAIL LABELS] Created new label '{new_name}' (ID: {chosen['id']})")

        resolved[key] = {"id": chosen["id"], "name": chosen.get("name", new_name)}
        print(f"[GMAIL LABELS] Resolved '{key}' -> ID={chosen['id']} name={chosen.get('name')}")

    return resolved


def ensure_safemailx_label_ids(service: Any) -> dict[str, str]:
    return {key: label["id"] for key, label in ensure_safemailx_labels(service).items()}


def move_message_to_queued_label(service: Any, message_id: str, label_ids: dict[str, str]) -> None:
    service.users().messages().modify(
        userId="me",
        id=message_id,
        body={
            "removeLabelIds": [label_ids["scan"]],
            "addLabelIds": [label_ids["queued"]],
        },
    ).execute()


def apply_result_label(service: Any, message_id: str, final_label: str, label_ids: dict[str, str]) -> None:
    result_key = RESULT_LABEL_BY_VERDICT.get(final_label, "failed")
    service.users().messages().modify(
        userId="me",
        id=message_id,
        body={
            "removeLabelIds": [label_ids["queued"]],
            "addLabelIds": [label_ids[result_key]],
        },
    ).execute()
