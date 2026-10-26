"""postman-hunter -- scan Postman public collections for hardcoded secrets.

A CLI that combines the secret-hunter pattern catalog with Postman
public-network recon: for each domain (and its resolved subdomains) it searches
the Postman public network, fetches the matching collections, and scans their
requests, variables, headers and bodies for secrets.  Results can optionally be
validated/classified by an LLM (Verboo, OpenRouter or Ollama).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from secret_hunter.classifier import classify_fallback
from secret_hunter.discovery import discover_subdomains, read_domains_file
from secret_hunter.patterns import extract_candidates
from secret_hunter.providers import ProviderConfig, LlmClient, ProviderError

from .postman_api import collection_text, fetch_collection, search_postman


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="postman-hunter",
        description="Search Postman public collections for a domain and scan them for hardcoded secrets.",
        epilog="Subdomain resolution is passive (certificate transparency), not DNS.",
    )
    p.add_argument("targets", nargs="*",
                   help="Domain(s) or URL(s) to search on the Postman public network.")
    p.add_argument("--domains-file", help="Text file with one domain per line; subdomains are resolved "
                                          "before the Postman search.")
    p.add_argument("--no-subdomains", action="store_true",
                   help="Do not resolve subdomains for the domains in --domains-file.")
    p.add_argument("--postman-api-key", help="Postman API key for more search results "
                                             "(or POSTMAN_API_KEY env var).")
    p.add_argument("--provider", choices=("verboo", "openrouter", "ollama"),
                   help="LLM provider to validate findings. Default from SECRET_HUNTER_PROVIDER or 'ollama'.")
    p.add_argument("--base-url", help="Override the LLM provider base URL.")
    p.add_argument("--api-key", help="Override the LLM provider API key.")
    p.add_argument("--model", help="Override the LLM provider model.")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip LLM validation; regex only.")
    p.add_argument("--mask-secrets", action="store_true",
                   help="Mask secret values in the report and before sending to a remote LLM.")
    p.add_argument("--max-collections", type=int, default=50,
                   help="Maximum collections to fetch and scan (default 50).")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout seconds (default 15).")
    p.add_argument("--concurrency", type=int, default=8,
                   help="Parallel fetches (default 8).")
    p.add_argument("--proxy", help="HTTP(S) proxy URL for all requests.")
    p.add_argument("-o", "--output", help="Write JSON report to this path.")
    p.add_argument("--quiet", action="store_true", help="Suppress the console summary.")
    return p


def _normalize_target(entry: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(entry.strip().lower())
    host = parsed.netloc or parsed.path or entry
    return host.split(":")[0].strip(".")


def _resolve_search_targets(args) -> tuple[list[str], dict[str, list[str]]]:
    """Build the list of domains/subdomains to search on Postman."""
    targets = [_normalize_target(t) for t in args.targets if _normalize_target(t)]
    subdomains: dict[str, list[str]] = {}

    if args.domains_file:
        try:
            domains = read_domains_file(args.domains_file)
        except ValueError as exc:
            raise SystemExit(f"[!] {exc}") from exc
        if args.no_subdomains:
            targets.extend(domains)
        else:
            subdomains = discover_subdomains(
                domains, timeout=args.timeout, concurrency=args.concurrency,
                proxy=args.proxy,
            )
            for apex, subs in subdomains.items():
                targets.append(apex)
                targets.extend(subs)

    seen: set[str] = set()
    final: list[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            final.append(t)
    return final, subdomains


def _search_all(targets: list[str], api_key: str | None, timeout: float,
                concurrency: int, proxy: str | None) -> list[dict]:
    """Search Postman for every target and merge the results."""
    all_results: list[dict] = []
    seen_ids: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(search_postman, t, api_key, timeout, proxy): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            for res in fut.result():
                eid = res.get("id")
                if eid and eid not in seen_ids:
                    seen_ids.add(eid)
                    all_results.append(res)
    return all_results


def _fetch_all_collections(ids: list[str], timeout: float, concurrency: int,
                           proxy: str | None) -> list[dict]:
    fetched: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(fetch_collection, cid, timeout, proxy): cid for cid in ids}
        for fut in concurrent.futures.as_completed(futures):
            data = fut.result()
            if data:
                fetched.append(data)
    return fetched


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        targets, subdomains = _resolve_search_targets(args)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1
    if not targets:
        print("[!] No targets. Provide a domain or use --domains-file.", file=sys.stderr)
        return 1

    api_key = args.postman_api_key or os.environ.get("POSTMAN_API_KEY")

    if not args.quiet:
        print(f"[*] Searching Postman for {len(targets)} domain(s)/subdomain(s)...")
    results = _search_all(targets, api_key, args.timeout, args.concurrency, args.proxy)

    # Scan search metadata (names/URLs) and then full collections.
    meta_text = "\n".join(
        f"{r.get('name', '')} {r.get('url', '')} {r.get('publisher', '')} {r.get('query', '')}"
        for r in results
    )
    candidates: list[Any] = extract_candidates(meta_text, "postman-search-results")

    collection_ids = [r["id"] for r in results if r.get("type") == "collection" and r.get("id")]
    collection_ids = list(dict.fromkeys(collection_ids))[: max(0, args.max_collections)]

    collections_fetched = 0
    requests_count = 0
    for coll in _fetch_all_collections(collection_ids, args.timeout, args.concurrency, args.proxy):
        collections_fetched += 1
        text = collection_text(coll)
        requests_count += _count_requests(coll)
        candidates.extend(extract_candidates(text, f"postman-collection:{coll.get('id', '?')}"))

    # Deduplicate candidates.
    dedup: dict[tuple[str, str], Any] = {}
    for c in candidates:
        key = (c.label, c.value)
        if key not in dedup:
            dedup[key] = c
    candidates = list(dedup.values())

    # ---- LLM validation --------------------------------------------------
    provider_name = args.provider
    client: LlmClient | None = None
    if not args.no_llm:
        try:
            config = ProviderConfig.from_env(
                provider=args.provider, base_url=args.base_url,
                api_key=args.api_key, model=args.model,
            )
            client = LlmClient(config)
            provider_name = config.name
        except (ValueError, ProviderError) as exc:
            print(f"[!] LLM disabled: {exc}", file=sys.stderr)
            provider_name = None

    analyses: dict[str, dict] = {}
    if client and candidates:
        for cand in candidates:
            key = f"{cand.label}::{cand.value}"
            try:
                analyses[key] = classify_fallback(client, cand, mask=args.mask_secrets).to_dict()
            except Exception as exc:  # noqa: BLE001
                analyses[key] = {"criticality": "Informational", "score": 0.0,
                                 "reportable": False, "impact": f"classification error: {exc}"}

    report = _build_report(
        candidates, analyses, targets, subdomains,
        results, collections_fetched, requests_count, provider_name,
        api_key is not None, mask=args.mask_secrets,
    )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            if not args.quiet:
                print(f"[+] JSON report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)
            return 1

    if not args.quiet:
        print(render_text(report))
    return 0


def _count_requests(collection_data: dict) -> int:
    count = 0
    data = collection_data.get("data", {}) or {}
    count += len(data.get("requests", []) or [])
    for item in (data.get("item", []) or []):
        count += _count_items(item)
    return count


def _count_items(item: dict) -> int:
    if "item" in item:
        return sum(_count_items(c) for c in item.get("item", []))
    if "request" in item:
        return 1
    return 0


def _build_report(candidates, analyses, targets, subdomains, results,
                  collections_fetched, requests_count, provider_name,
                  postman_key_used, mask=False) -> dict:
    findings = []
    for cand in candidates:
        key = f"{cand.label}::{cand.value}"
        finding = {**cand.to_dict(), "analysis": analyses.get(key)}
        if mask:
            finding["value"] = cand.masked()
            finding["masked"] = cand.masked()
        else:
            finding.pop("masked", None)
        findings.append(finding)

    def sort_key(f):
        a = f.get("analysis") or {}
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                 "Informational": 4, "FalsePositive": 5}
        return (order.get(a.get("criticality", "Informational"), 5),
                -(a.get("score", 0.0) or 0.0))
    findings.sort(key=sort_key)

    return {
        "tool": "postman-hunter",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "postman_api_key_used": postman_key_used,
        "provider": provider_name,
        "subdomains_discovered": {a: s for a, s in (subdomains or {}).items()},
        "postman_entities_found": len(results),
        "collections_scanned": collections_fetched,
        "requests_scanned": requests_count,
        "candidates_found": len(candidates),
        "findings": findings,
    }


def render_text(report: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(" POSTMAN-HUNTER REPORT")
    lines.append("=" * 78)
    lines.append(f" Targets            : {', '.join(report['targets'])}")
    lines.append(f" Postman API key    : {'yes' if report['postman_api_key_used'] else 'no'}")
    lines.append(f" LLM provider       : {report['provider'] or '(none - regex only)'}")
    lines.append(f" Subdomains         : {sum(len(v) for v in report['subdomains_discovered'].values())} discovered")
    lines.append(f" Postman entities   : {report['postman_entities_found']}")
    lines.append(f" Collections scanned: {report['collections_scanned']}")
    lines.append(f" Requests scanned   : {report['requests_scanned']}")
    lines.append(f" Candidates         : {report['candidates_found']}")
    lines.append("")
    lines.append(f" {'CRITICALITY':<16}{'SCORE':<7}{'TYPE':<26}{'VALUE':<40}")
    lines.append("-" * 78)
    for f in report["findings"]:
        a = f.get("analysis") or {}
        crit = a.get("criticality", "Informational")
        score = f"{a.get('score', 0.0):.1f}"
        lines.append(f" {crit:<16}{score:<7}{f['type']:<26}{f.get('value', ''):<40}")
        if a.get("explanation"):
            lines.append(f"   -> {a['explanation']}")
        if a.get("impact"):
            lines.append(f"   impact: {a['impact']}")
        if a.get("remediation"):
            lines.append(f"   fix: {a['remediation']}")
        lines.append(f"   source: {f['source']}")
        lines.append("")
    return "\n".join(lines)
