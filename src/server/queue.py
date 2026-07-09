import json
from typing import Any

import redis

from server.settings import REDIS_URL


QUEUE_NAME = "safemailx:scan-jobs"


class QueueUnavailable(RuntimeError):
    pass


class ScanQueue:
    def __init__(self, redis_url: str = REDIS_URL, queue_name: str = QUEUE_NAME) -> None:
        self.redis_url = redis_url
        self.queue_name = queue_name

    def _client(self):
        return redis.from_url(self.redis_url, socket_connect_timeout=2, socket_timeout=2)

    def enqueue(self, job: dict[str, Any]) -> int:
        try:
            payload = json.dumps(job)
            return int(self._client().rpush(self.queue_name, payload))
        except redis.RedisError as exc:
            raise QueueUnavailable(str(exc)) from exc

    def ping(self) -> bool:
        try:
            return bool(self._client().ping())
        except redis.RedisError:
            return False
