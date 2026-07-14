SQLITE_PERSISTENCE_WARNING = (
    "[APP] WARNING: DATABASE_URL is using local SQLite. "
    "Data will NOT survive a restart on most hosting platforms "
    "(Render/Koyeb free tiers included). Set DATABASE_URL to a "
    "persistent Postgres instance for production use."
)


def check_database_persistence(database_url: str) -> str | None:
    if database_url.startswith("sqlite:///"):
        return SQLITE_PERSISTENCE_WARNING
    return None
