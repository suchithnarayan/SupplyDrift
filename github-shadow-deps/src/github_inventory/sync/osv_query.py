"""Point-in-time OSV malware (MAL-*) check for scanned components — stdlib only.

The scanner's ``--malware`` flag uses this to query OSV's ``/v1/querybatch`` over
the SBOM it just built (by purl when available) and keep results whose advisory id
starts with ``MAL-``. Malicious hits become ``finding_type='malware'`` findings on
the payload. Degrades to a no-op on any network error (never fails a scan).
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

OSV_API = "https://api.osv.dev/v1"
_CANON_TO_OSV = {
    "npm": "npm", "pypi": "PyPI", "python": "PyPI", "golang": "Go", "go": "Go",
    "gem": "RubyGems", "rubygems": "RubyGems", "cargo": "crates.io", "composer": "Packagist",
    "php": "Packagist", "maven": "Maven", "java": "Maven", "nuget": "NuGet", "hex": "Hex", "pub": "Pub",
}


def _osv_eco(canon: str) -> str:
    return _CANON_TO_OSV.get((canon or "").strip().lower(), "")


def _post_json(url: str, body: dict, timeout: int) -> Any:
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "supplydrift-osv/1"},
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def query_components(
    components: list[dict],
    *,
    post_json: Callable[[str, dict], Any] | None = None,
    api_url: str = OSV_API,
    timeout: int = 30,
    batch_size: int = 500,
) -> list[dict]:
    """Return components with OSV MAL-* advisories: ``{name, version, ecosystem, purl, advisory_ids}``."""
    post = post_json if post_json is not None else (lambda u, b: _post_json(u, b, timeout))
    order: list[tuple] = []
    seen: set = set()
    for comp in components:
        name = (comp.get("name") or "").strip()
        purl = (comp.get("purl") or "").strip()
        version = (comp.get("version") or "").strip()
        osv_eco = _osv_eco(comp.get("ecosystem") or "")
        if not purl and not (name and osv_eco):
            continue  # can't query precisely -> skip (avoids cross-ecosystem false positives)
        key = purl or (name, osv_eco, version)
        if key in seen:
            continue
        seen.add(key)
        order.append((comp, name, purl, version, osv_eco))

    hits: list[dict] = []
    for start in range(0, len(order), batch_size):
        chunk = order[start:start + batch_size]
        queries = []
        for (_comp, name, purl, version, osv_eco) in chunk:
            if purl:
                queries.append({"package": {"purl": purl}})
            else:
                q: dict = {"package": {"name": name, "ecosystem": osv_eco}}
                if version:
                    q["version"] = version
                queries.append(q)
        resp = post(f"{api_url}/querybatch", {"queries": queries})
        results = (resp or {}).get("results") or []
        for (comp, name, purl, version, _eco), res in zip(chunk, results):
            mal = [str(v.get("id")) for v in ((res or {}).get("vulns") or [])
                   if str(v.get("id", "")).startswith("MAL-")]
            if mal:
                hits.append({"name": name, "version": version, "ecosystem": comp.get("ecosystem") or "",
                             "purl": purl, "advisory_ids": mal})
    return hits


def enrich_payload_with_malware(payload: dict, **query_kw) -> int:
    """Append finding_type='malware' findings to a normalized payload (in place).

    Returns the number of findings added. Safe to call on any payload.
    """
    comps = payload.get("components") or []
    if not comps:
        return 0
    hits = query_components(comps, **query_kw)
    if not hits:
        return 0
    asset_ref = (payload.get("assets") or [{}])[0].get("ref")
    by_purl = {c.get("purl"): c for c in comps if c.get("purl")}
    by_nv = {(c.get("name"), c.get("version")): c for c in comps}
    findings = payload.setdefault("findings", [])
    added = 0
    for hit in hits:
        comp = by_purl.get(hit.get("purl")) or by_nv.get((hit["name"], hit["version"]))
        ref = comp.get("ref") if comp else None
        for adv in hit["advisory_ids"]:
            findings.append({
                "asset_ref": asset_ref, "component_ref": ref,
                "finding_type": "malware", "severity": "critical", "title": adv,
                "description": f"Malicious package {hit['name']}@{hit['version']} flagged by OSV ({adv})",
                "fix_recommendation": f"Remove or replace {hit['name']}; flagged malicious by OSV",
                "evidence": {"advisory_id": adv, "advisory_url": f"https://osv.dev/{adv}",
                             "package": hit["name"], "version": hit["version"]},
            })
            added += 1
    return added
