"""Postman public-network access helpers.

Adapted from a Postman public-network recon scanner.  It searches the Postman
public network for collections related to a domain, fetches those collections,
and flattens them into text suitable for the secret pattern catalog.

Two search paths are used:

* The Postman web search proxy (works without an API key).
* The official search API when a Postman API key is supplied (more results).
"""

from __future__ import annotations

import json
import os
import re
import time
from urllib.parse import quote

import requests

# Endpoints; each can be overridden with an env var (useful for tests or a
# self-hosted Postman frontend).  Placeholders are replaced at call time.
SEARCH_PROXY = os.environ.get("POSTMAN_SEARCH_PROXY",
                              "https://www.postman.com/_api/ws/proxy")
WORKSPACE_URL = os.environ.get("POSTMAN_WORKSPACE_URL",
                               "https://www.postman.com/_api/workspace/{wid}")
COLLECTION_URL = os.environ.get("POSTMAN_COLLECTION_URL",
                                "https://www.postman.com/_api/collection/{cid}?populate=true")
COLLECTION_URL_NO_POPULATE = os.environ.get("POSTMAN_COLLECTION_URL_NO_POPULATE",
                                            "https://www.postman.com/_api/collection/{cid}")
API_SEARCH_URL = os.environ.get("POSTMAN_API_SEARCH_URL",
                                "https://api.getpostman.com/search?query={query}&type={type}")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _session(proxy: str | None = None, timeout: float = 15.0) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _search_queries(domain: str) -> list[str]:
    """Build a small set of search terms for a domain (full + base + variants)."""
    queries = [domain]
    parts = domain.replace("www.", "").split(".")
    if len(parts) >= 2:
        base = parts[0]
        queries.append(base)
        queries.append(f"{base} api")
        queries.append(f"{base} seller")
    return list(dict.fromkeys(q for q in queries if q))


def search_postman(domain: str, api_key: str | None = None,
                   timeout: float = 15.0, proxy: str | None = None) -> list[dict]:
    """Search the Postman public network for entities related to *domain*."""
    results: list[dict] = []
    seen: set[str] = set()
    session = _session(proxy, timeout)

    # ---- Method 1: public search proxy (no key required) -----------------
    for query in _search_queries(domain):
        for indices in (
            ["runtime.collection", "runtime.request"],
            ["runtime.collection"],
            ["runtime.request"],
            ["runtime.workspace"],
        ):
            try:
                r = session.post(
                    SEARCH_PROXY,
                    json={
                        "service": "search",
                        "method": "POST",
                        "path": "/search-all",
                        "body": {"queryIndices": indices, "queryText": query, "size": 25},
                    },
                    timeout=timeout,
                )
                if r.status_code != 200:
                    continue
                data = r.json().get("data", {})
                for entity_type in ("collection", "request", "workspace"):
                    for item in data.get(entity_type, []):
                        doc = item.get("document", {})
                        eid = str(doc.get("id", ""))
                        if not eid or eid in seen:
                            continue
                        seen.add(eid)
                        results.append({
                            "type": entity_type,
                            "name": doc.get("name", ""),
                            "id": eid,
                            "publisher": doc.get("publisherHandle", ""),
                            "workspace": doc.get("workspaceName", ""),
                            "workspaceId": doc.get("workspaceId", ""),
                            "url": doc.get("url", ""),
                            "method": doc.get("method", ""),
                            "score": item.get("score", 0),
                            "query": query,
                            "source": "proxy",
                        })
                time.sleep(0.3)
            except requests.RequestException:
                continue

    # ---- Method 2: workspace collections ---------------------------------
    workspace_ids: set[str] = set()
    for res in results:
        if res.get("type") == "workspace" and res.get("id"):
            workspace_ids.add(res["id"])
        if res.get("workspaceId"):
            workspace_ids.add(res["workspaceId"])
    for wid in list(workspace_ids)[:5]:
        try:
            wr = session.get(WORKSPACE_URL.format(wid=wid), timeout=timeout)
            if wr.status_code != 200:
                continue
            wdata = wr.json().get("data", {})
            for cid in wdata.get("dependencies", {}).get("collections", []):
                cid = str(cid)
                if cid not in seen:
                    seen.add(cid)
                    results.append({
                        "type": "collection",
                        "name": f"[workspace:{wdata.get('name', '')}]",
                        "id": cid,
                        "publisher": "",
                        "workspace": wdata.get("name", ""),
                        "source": "workspace",
                    })
        except requests.RequestException:
            continue

    # ---- Method 3: official search API (requires a key) ------------------
    if api_key:
        for entity in ("collection", "workspace", "api"):
            try:
                r = session.get(
                    API_SEARCH_URL.format(query=quote(domain), type=entity),
                    headers={"X-Api-Key": api_key},
                    timeout=timeout,
                )
                if r.status_code != 200:
                    continue
                for item in r.json().get("data", []):
                    eid = str(item.get("id", ""))
                    if not eid or eid in seen:
                        continue
                    seen.add(eid)
                    results.append({
                        "type": entity,
                        "name": item.get("name", ""),
                        "id": eid,
                        "publisher": item.get("publisherName", ""),
                        "source": "api_key",
                    })
            except requests.RequestException:
                continue

    return results


def fetch_collection(collection_id: str, timeout: float = 15.0,
                     proxy: str | None = None) -> dict | None:
    """Fetch the full JSON of a public collection, or None on failure."""
    session = _session(proxy, timeout)
    for url in (COLLECTION_URL, COLLECTION_URL_NO_POPULATE):
        try:
            r = session.get(url.format(cid=collection_id), timeout=timeout)
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            continue
    return None


def collection_text(collection_data: dict | None) -> str:
    """Flatten a collection into a text blob for the secret pattern catalog.

    The full JSON is scanned (covers every field), plus the request URLs,
    headers, bodies, variables and auth are rendered as text so that values
    hidden behind nested structures are still reached.
    """
    if not collection_data:
        return ""
    parts: list[str] = []

    data = collection_data.get("data", {}) or {}

    # Collection-level variables.
    variables = data.get("variable", []) or data.get("variables", []) or []
    for var in variables:
        if isinstance(var, dict):
            parts.append(f"key={var.get('key', '')} value={var.get('value', '')}")

    # Requests (legacy flat + v2 nested).
    for req in _iter_requests(data):
        url = req.get("url", "")
        if isinstance(url, dict):
            url = url.get("raw", "")
        parts.append(req.get("name", ""))
        parts.append(req.get("method", ""))
        parts.append(str(url))
        for h in (req.get("header", []) or req.get("headerData", []) or []):
            if isinstance(h, dict) and h.get("key"):
                parts.append(f"{h.get('key')}: {h.get('value', '')}")
        body = req.get("body", "")
        if isinstance(body, dict):
            body = body.get("raw", "") or json.dumps(body.get("formdata", []))
        parts.append(str(body))
        parts.append(json.dumps(req.get("auth", {}), ensure_ascii=False))

    # The whole document as JSON, so nothing is missed.
    parts.append(json.dumps(collection_data, ensure_ascii=False))
    return "\n".join(p for p in parts if p)


def _iter_requests(data: dict):
    """Yield request-like dicts from legacy and v2 collection shapes."""
    for req in data.get("requests", []):
        if isinstance(req, dict):
            yield req
    for item in (data.get("item", []) or []):
        yield from _walk_items(item)


def _walk_items(item: dict):
    if "item" in item:
        for child in item.get("item", []):
            yield from _walk_items(child)
    elif "request" in item:
        yield {"name": item.get("name", ""), **item.get("request", {})}
