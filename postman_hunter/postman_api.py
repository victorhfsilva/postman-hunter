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
# Public web front-end base, used to build human-openable links to entities.
PUBLIC_BASE = os.environ.get("POSTMAN_PUBLIC_BASE", "https://www.postman.com").rstrip("/")

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


def collection_uuid(raw_id: str | None) -> str:
    """Return the bare collection UUID from a Postman id.

    Search hits expose ids shaped like ``<ownerId>-<uuid>`` (e.g.
    ``665823-2664f86d-f802-463a-b731-b68d6821464b``) while the fetched
    collection document reports the bare UUID under ``data.id``.  This helper
    normalizes either form to the bare UUID used in public links.
    """
    if not raw_id:
        return ""
    parts = str(raw_id).split("-", 1)
    if len(parts) == 2 and parts[0].isdigit() and "-" in parts[1]:
        return parts[1]
    return str(raw_id)


def collection_url(uuid: str | None, workspace_slug: str | None = None) -> str:
    """Build a human-openable Postman link for a collection, when possible.

    The canonical public URL is ``/{workspace-slug}/collection/{uuid}``.  A
    workspace slug is required to render it; when it is unknown an empty string
    is returned rather than a link that 404s.
    """
    uuid = collection_uuid(uuid)
    if not uuid:
        return ""
    slug = (workspace_slug or "").strip("/")
    if slug:
        return f"{PUBLIC_BASE}/{slug}/collection/{uuid}"
    return ""


def entity_url(entity_type: str, raw_id: str | None,
               workspace_slug: str | None = None) -> str:
    """Best-effort public URL for a search entity (collection/workspace/request)."""
    if entity_type == "collection":
        return collection_url(raw_id, workspace_slug)
    if entity_type == "workspace" and workspace_slug:
        return f"{PUBLIC_BASE}/{workspace_slug.strip('/')}"
    return ""


def collection_meta(collection_data: dict | None, requested_id: str | None = None,
                    search_meta: dict | None = None) -> dict:
    """Resolve a fetched collection's identity for finding attribution.

    Returns the bare collection id, its display name, publisher/workspace facts
    and a public URL (or an empty string when a link cannot be built).
    """
    data = (collection_data or {}).get("data", {}) or {}
    search_meta = search_meta or {}
    uuid = data.get("id") or (collection_data or {}).get("model_id") or ""
    public_id = str(requested_id or search_meta.get("id") or "")
    if not uuid:
        uuid = collection_uuid(public_id)
    name = data.get("name") or search_meta.get("name") or ""
    slug = search_meta.get("workspaceSlug") or search_meta.get("workspace_slug") or ""
    ident = uuid or public_id or "?"
    return {
        "id": uuid,
        "public_id": public_id or uuid,
        "name": name,
        "publisher": search_meta.get("publisher") or "",
        "workspace": search_meta.get("workspace") or "",
        "workspace_slug": slug,
        "url": collection_url(uuid, slug),
        "source": f"postman-collection:{ident}",
    }


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
                        slug = doc.get("workspaceSlug", "")
                        results.append({
                            "type": entity_type,
                            "name": doc.get("name", ""),
                            "id": eid,
                            "publisher": doc.get("publisherHandle", ""),
                            "workspace": doc.get("workspaceName", ""),
                            "workspaceId": doc.get("workspaceId", ""),
                            "workspaceSlug": slug,
                            "url": doc.get("url", "") or entity_url(entity_type, eid, slug),
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


def _request_text(req: dict) -> str:
    """Render one request as text: name, method, url, headers, body, auth."""
    parts: list[str] = []
    parts.append(str(req.get("name", "")))
    parts.append(str(req.get("method", "")))
    url = req.get("url", "")
    if isinstance(url, dict):
        url = url.get("raw", "")
    parts.append(str(url))
    for h in (req.get("headerData") or req.get("header") or []):
        if isinstance(h, dict) and h.get("key"):
            parts.append(f"{h.get('key')}: {h.get('value', '')}")
        elif isinstance(h, str):
            parts.append(h)
    if isinstance(req.get("headers"), str):
        parts.append(req["headers"])
    body = req.get("rawModeData")
    if not body:
        body = req.get("body") or req.get("data")
    if isinstance(body, dict):
        body = body.get("raw") or json.dumps(body.get("formdata", []), ensure_ascii=False)
    elif isinstance(body, list):
        body = json.dumps(body, ensure_ascii=False)
    parts.append(str(body) if body else "")
    if req.get("auth"):
        parts.append(json.dumps(req.get("auth", {}), ensure_ascii=False))
    return "\n".join(p for p in parts if p)


def collection_segments(collection_data: dict | None) -> list[tuple[str, str]]:
    """Split a collection into labelled text segments for attributed scanning.

    Returns ``(label, text)`` pairs: one for collection-level variables/auth,
    one per request (labelled with its folder/name path) and a final full
    document segment so nothing nested is missed.  The label lets callers record
    *where inside the collection* a candidate was found.
    """
    if not collection_data:
        return []
    data = collection_data.get("data", {}) or {}
    segments: list[tuple[str, str]] = []

    variables = data.get("variables") or data.get("variable") or []
    vparts: list[str] = []
    for var in variables:
        if isinstance(var, dict):
            vparts.append(f"key={var.get('key', '')} value={var.get('value', '')}")
    if vparts:
        segments.append(("collection variables", "\n".join(vparts)))

    if data.get("auth"):
        segments.append(("collection auth", json.dumps(data["auth"], ensure_ascii=False)))

    for path, req in _iter_requests_with_path(data):
        segments.append((path or "(request)", _request_text(req)))

    segments.append(("(full document)", json.dumps(collection_data, ensure_ascii=False)))
    return segments


def collection_text(collection_data: dict | None) -> str:
    """Flatten a collection into a single text blob for the secret catalog."""
    return "\n".join(text for _, text in collection_segments(collection_data))


def _folder_names(data: dict) -> dict[str, str]:
    names: dict[str, str] = {}
    for f in (data.get("folders") or []):
        if isinstance(f, dict) and f.get("id"):
            names[str(f["id"])] = f.get("name", "") or ""
    return names


def _iter_requests_with_path(data: dict):
    """Yield ``(path, request)`` for legacy flat and v2 nested collections."""
    folder_names = _folder_names(data)
    for req in (data.get("requests", []) or []):
        if isinstance(req, dict):
            fname = folder_names.get(str(req.get("folder", "")), "")
            path = f"{fname} / {req.get('name', '')}".strip(" /")
            yield path, req
    for item in (data.get("item", []) or []):
        yield from _walk_items_with_path(item, "")


def _walk_items_with_path(item: dict, prefix: str):
    name = item.get("name", "") or ""
    if "item" in item:
        new_prefix = f"{prefix} / {name}".strip(" /") if name else prefix
        for child in item.get("item", []):
            yield from _walk_items_with_path(child, new_prefix)
    elif "request" in item:
        path = f"{prefix} / {name}".strip(" /") if prefix else name
        req = item.get("request", {})
        if isinstance(req, str):
            req = {"url": req}
        yield path, {"name": name, **req}


def _iter_requests(data: dict):
    """Yield request-like dicts from legacy and v2 collection shapes."""
    for _, req in _iter_requests_with_path(data):
        yield req


def _walk_items(item: dict):
    for _, req in _walk_items_with_path(item, ""):
        yield req

