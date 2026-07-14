"""Deliver a scan payload to the SupplyDrift platform (or to a file)."""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SYNC_PATH = "/api/sync/kubernetes-workloads"


def push_to_platform(base_url: str, payload: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    """POST the payload to the platform's Kubernetes sync endpoint."""
    from image_scanner.config import auth_headers

    url = base_url.rstrip("/") + SYNC_PATH
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", **auth_headers()}
    request = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8") or "{}"
            return {"status": response.status, "response": json.loads(body)}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"platform returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"could not reach platform at {url}: {exc.reason}") from exc
