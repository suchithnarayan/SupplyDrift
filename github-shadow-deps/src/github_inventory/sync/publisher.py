"""POST a repository scan payload to the platform."""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SYNC_PATH = "/api/sync/repositories"


def push_repo(platform_url: str, payload: dict[str, Any], timeout: int = 120) -> None:
    from .config import auth_headers

    url = platform_url.rstrip("/") + SYNC_PATH
    data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json", **auth_headers()}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(f"platform returned HTTP {response.status}")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"platform returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"could not reach platform at {url}: {exc.reason}") from exc
