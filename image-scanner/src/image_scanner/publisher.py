"""POST scanned image SBOMs to the SupplyDrift platform."""
from __future__ import annotations

import gzip
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SYNC_PATH = "/api/sync/container-images"


def push_image(
    base_url: str, payload: dict[str, Any], timeout: int = 120, compress: bool = True
) -> dict[str, Any]:
    """POST one compact image payload to the container-image sync endpoint.

    The body is gzip-compressed by default (the platform decodes
    ``Content-Encoding: gzip``) to keep large image inventories small on the wire.
    """
    from .config import auth_headers

    url = base_url.rstrip("/") + SYNC_PATH
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", **auth_headers()}
    if compress:
        data = gzip.compress(data)
        headers["Content-Encoding"] = "gzip"
    request = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8") or "{}"
            return {"status": response.status, "response": json.loads(body)}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"platform returned HTTP {exc.code}: {detail[:300]}") from exc
    except URLError as exc:
        raise RuntimeError(f"could not reach platform at {url}: {exc.reason}") from exc
