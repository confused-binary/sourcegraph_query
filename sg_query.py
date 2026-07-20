#!/usr/bin/env python3
"""
Sourcegraph AWS resource frequency pipeline.

Fetches AWS/Terraform resource type lists, queries Sourcegraph for per-service
frequency, analyzes surface area, and builds a fuzzy CFN-to-TF resource map.
Writes merged results to a single CSV.

Keeps a tracking file (sg_tracking.json) that records completed services.
If interrupted, rerun the same command and it picks up where it left off.
Once all services finish, the tracking file is removed automatically.

    SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py
    SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py --output results.csv
    SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py --service ec2 --service s3
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from difflib import SequenceMatcher

log = logging.getLogger("sg_query")

try:
    import requests
except ImportError:
    requests = None

ENDPOINT = "https://sourcegraph.com/.api/search/stream"
CFN_RE = re.compile(r"^AWS::(\w+)::(\w+)$")
TRACKING_FILE = "sg_tracking.json"

CFN_SPEC_URL = (
    "https://d1uauaxba7bl26.cloudfront.net/latest/gzip/"
    "CloudFormationResourceSpecification.json"
)
TF_REGISTRY_BASE = "https://registry.terraform.io"

MERGED_FIELDS = [
    "service", "tf_match_count", "cfn_match_count",
    "tf_repo_count", "cfn_repo_count",
    "tf_resource_count", "cfn_resource_count",
    "combined_resource_count", "error",
]

DATA_FIELDS = ["repo_url", "file", "iac_type", "filter", "match"]

MAP_FIELDS = ["tf_resource", "cfn_resource", "similarity", "service"]

RESOURCE_COUNT_FIELDS = ["resource_type", "match_count", "repo_count"]

_TF_RES_RE = re.compile(r'resource\s+"(aws_[a-z0-9_]+)"')
_CFN_RES_RE = re.compile(r'(AWS::\w+::\w+)')


# ---------------------------------------------------------------------------
# Tracking file
# ---------------------------------------------------------------------------

def _load_tracking(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("services", {})


def _save_tracking(path, services):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"services": services}, fh, indent=2)
    os.replace(tmp, path)


def _is_complete(row):
    if row.get("error"):
        return False
    return any(
        row.get(f) not in (None, "", 0)
        for f in ("tf_match_count", "cfn_match_count")
    )


# ---------------------------------------------------------------------------
# Sourcegraph API
# ---------------------------------------------------------------------------

def _require_requests():
    if requests is None:
        sys.exit("ERROR: 'requests' package required (pip install requests).")


def _get_token():
    token = os.environ.get("SOURCEGRAPH_TOKEN")
    if not token:
        sys.exit(
            "ERROR: SOURCEGRAPH_TOKEN not set.\n"
            "Generate at https://sourcegraph.com/user/settings/tokens\n"
            "  SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py"
        )
    return token


def _build_session(token):
    s = requests.Session()
    s.headers.update({
        "Accept": "text/event-stream",
        "Authorization": f"token {token}",
    })
    return s


def _iter_sse(resp, flush):
    event = None
    buf = []
    for raw in resp.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        line = raw.rstrip("\r")
        if line == "":
            flush(event, buf)
            event, buf = None, []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            buf.append(line[len("data:"):].lstrip())
    flush(event, buf)


def _parse_json(buf):
    try:
        return json.loads("\n".join(buf))
    except json.JSONDecodeError:
        return None


def _check_limit(payload):
    for skip in payload.get("skipped", []) or []:
        reason = (skip.get("reason") or "").lower()
        if "limit" in reason or "shard" in reason:
            return True
    return False


def _parse_alert(payload):
    title = payload.get("title") or ""
    desc = payload.get("description") or ""
    return (title + " " + desc).strip() or None


_COLLAPSE_WS = re.compile(r"[\r\n\t]+")
_MAX_MATCH = 200


def _clean_match(raw):
    s = _COLLAPSE_WS.sub(" ", raw).strip()
    if len(s) > _MAX_MATCH:
        s = s[:_MAX_MATCH]
    return s


def _extract_match_lines(line_matches, chunk_matches):
    if isinstance(line_matches, list) and line_matches:
        return [_clean_match(lm.get("line", "")) for lm in line_matches]
    if isinstance(chunk_matches, list) and chunk_matches:
        return [_clean_match(cm.get("content", "")) for cm in chunk_matches]
    return []


def _parse_aggregate(resp):
    progress_count = None
    match_lines = 0
    seen_matches = False
    limit_hit = False
    alert = None
    repos = set()
    details = []

    def flush(evt, buf):
        nonlocal progress_count, match_lines, seen_matches, limit_hit, alert
        if not evt or not buf:
            return
        payload = _parse_json(buf)
        if payload is None:
            return
        if evt == "progress":
            mc = payload.get("matchCount")
            if isinstance(mc, int):
                progress_count = mc
            if _check_limit(payload):
                limit_hit = True
        elif evt == "matches" and isinstance(payload, list):
            seen_matches = True
            for m in payload:
                repo = m.get("repository") or ""
                path = m.get("path") or ""
                if repo:
                    repos.add(repo)
                lm = m.get("lineMatches")
                cm = m.get("chunkMatches")
                lines = _extract_match_lines(lm, cm)
                match_lines += max(len(lines), 1)
                for line in lines:
                    details.append({
                        "repo_url": f"https://{repo}" if repo else "",
                        "file": path,
                        "match": line,
                    })
        elif evt == "alert":
            alert = _parse_alert(payload)

    _iter_sse(resp, flush)
    total = progress_count if progress_count is not None else (match_lines if seen_matches else 0)
    return {"match_count": total, "repo_count": len(repos), "limit_hit": limit_hit, "alert": alert, "details": details}


_QUERY_NOISE_RE = re.compile(
    r"^context:\S+\s+(?:file:\S+\s+)?patterntype:\S+\s+count:\S+\s+(?:fork:\S+\s+)?"
)


def _log_query(query):
    return _QUERY_NOISE_RE.sub("", query)[:80]


def _run_query(session, query, endpoint=ENDPOINT, parser=None):
    if parser is None:
        parser = _parse_aggregate
    log.debug("query: %s", _log_query(query))
    try:
        start = time.monotonic()
        with session.get(endpoint, params={"q": query}, stream=True, timeout=120) as resp:
            elapsed = time.monotonic() - start
            if resp.status_code != 200:
                log.warning("HTTP %d in %.1fs -- %s", resp.status_code, elapsed, _log_query(query))
                return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
            result = parser(resp)
            log.debug("%.1fs  %s", elapsed, _log_query(query))
            return result, None
    except requests.RequestException as exc:
        log.warning("request failed: %s -- %s", exc, _log_query(query))
        return None, f"request failed: {exc}"


# ---------------------------------------------------------------------------
# Fetch resource types
# ---------------------------------------------------------------------------

def _fetch_cfn_types():
    log.debug("fetching CFN spec from %s", CFN_SPEC_URL)
    resp = requests.get(CFN_SPEC_URL, timeout=60)
    resp.raise_for_status()
    return sorted(resp.json().get("ResourceTypes", {}).keys())


def _fetch_tf_types():
    url = f"{TF_REGISTRY_BASE}/v2/providers"
    resp = requests.get(url, params={"filter[namespace]": "hashicorp", "filter[name]": "aws"}, timeout=60)
    resp.raise_for_status()
    providers = resp.json().get("data", [])
    if not providers:
        raise RuntimeError("hashicorp/aws provider not found")

    pid = providers[0]["id"]
    url = f"{TF_REGISTRY_BASE}/v2/providers/{pid}/provider-versions"
    resp = requests.get(url, params={"page[size]": "100"}, timeout=60)
    resp.raise_for_status()
    versions = resp.json().get("data", [])
    if not versions:
        raise RuntimeError("No versions for hashicorp/aws")

    latest = max(versions, key=lambda v: [
        int(x) for x in v.get("attributes", {}).get("version", "0.0.0").split(".")
        if x.isdigit()
    ])
    vid = latest["id"]
    ver = latest.get("attributes", {}).get("version", "?")

    resources = []
    base_url = f"{TF_REGISTRY_BASE}/v2/provider-docs"
    params = {"filter[provider-version]": vid, "filter[category]": "resources", "page[size]": "100"}
    page = 1
    while True:
        p = {**params, "page[number]": str(page)}
        resp = requests.get(base_url, params=p, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", [])
        if not items:
            break
        for item in items:
            title = item.get("attributes", {}).get("title", "")
            if title:
                resources.append(title if title.startswith("aws_") else f"aws_{title}")
        meta = data.get("meta", {}).get("pagination", {})
        nxt = meta.get("next-page")
        if nxt and int(nxt) > page:
            page = int(nxt)
        elif len(items) == 100:
            page += 1
        else:
            break

    return sorted(set(resources))


def _fetch_all_types():
    _require_requests()
    print("Fetching resource types... ", end="", flush=True)
    cfn = _fetch_cfn_types()
    tf = _fetch_tf_types()
    print()
    print(f"CloudFormation: {len(cfn)}")
    print(f"Terraform:      {len(tf)}")
    print()
    return cfn, tf


# ---------------------------------------------------------------------------
# Service catalog + query building
# ---------------------------------------------------------------------------

def _derive_catalog(cfn_types, tf_types, tf_to_service=None):
    if tf_to_service is None:
        tf_to_service = {}

    cfn_ns = {}
    for t in cfn_types:
        m = CFN_RE.match(t)
        if m:
            cfn_ns.setdefault(m.group(1).lower(), m.group(1))

    service_tf_prefixes = defaultdict(set)
    for t in tf_types:
        parts = t.split("_")
        if len(parts) >= 2 and parts[0] == "aws":
            naive_prefix = parts[1]
            service = tf_to_service.get(t, naive_prefix)
            service_tf_prefixes[service].add(naive_prefix)

    catalog = []
    for key in sorted(set(cfn_ns.keys()) | set(service_tf_prefixes.keys())):
        entry = {"name": key}
        if key in cfn_ns:
            entry["cfn"] = cfn_ns[key]
        if key in service_tf_prefixes:
            entry["tf_prefixes"] = sorted(service_tf_prefixes[key])
        catalog.append(entry)
    return catalog


def _tf_query(prefix):
    return (f'context:global file:\\.tf$ patterntype:regexp count:all fork:no '
            f'resource\\s+["]aws_{prefix}[_"]')


def _cfn_query(svc, ext):
    return (f'context:global file:\\.{ext}$ patterntype:regexp count:all fork:no '
            f'Type"?\\s*[:].*AWS::{svc["cfn"]}::')


CFN_EXTENSIONS = [("yaml", "YAML"), ("yml", "YML"), ("json", "JSON")]


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def _query_services(catalog, session, delay, endpoint, tracked, tracking_path):
    total = len(catalog)
    cached = sum(1 for s in catalog if _is_complete(tracked.get(s["name"], {})))
    remaining = total - cached
    print(f"Querying {total} services ({cached} complete, {remaining} remaining, delay {delay}s)\n")

    done = cached
    query_errors = 0
    rows = []
    all_details = []
    queries_run = 0

    for i, svc in enumerate(catalog, 1):
        name = svc["name"]

        prev = tracked.get(name, {})
        if _is_complete(prev):
            rows.append(prev)
            continue

        pct = done * 100 // total if total else 0
        prefix = f"[{i}/{total} {pct:>3}%] {name}"

        row = {"service": name, "tf_match_count": "", "cfn_match_count": "",
               "tf_repo_count": "", "cfn_repo_count": "", "error": ""}

        cfn_filter = f'AWS::{svc["cfn"]}::' if "cfn" in svc else None

        if "tf_prefixes" in svc:
            tf_match_total = 0
            tf_repos = set()
            for tf_pfx in svc["tf_prefixes"]:
                tf_filter = f'aws_{tf_pfx}'
                if queries_run > 0 and delay > 0:
                    time.sleep(delay)
                result, error = _run_query(session, _tf_query(tf_pfx), endpoint)
                queries_run += 1
                if error:
                    print(f"{prefix} terraform {tf_filter} ERROR ({error})")
                    row["error"] = error
                    break
                mc, rc = result["match_count"], result["repo_count"]
                warn = " (shard limit -- count is a floor)" if result.get("limit_hit") else ""
                print(f"{prefix} terraform {tf_filter} {mc} matches {rc} repos{warn}")
                tf_match_total += mc
                for d in result.get("details", []):
                    repo = d.get("repo_url", "")
                    if repo:
                        tf_repos.add(repo)
                    d["iac_type"] = "terraform"
                    d["filter"] = tf_filter
                    all_details.append(d)
            if not row.get("error"):
                row["tf_match_count"] = tf_match_total
                row["tf_repo_count"] = len(tf_repos)

        if "cfn" in svc and not row.get("error"):
            cfn_match_total = 0
            cfn_repos = set()
            for ext, ext_label in CFN_EXTENSIONS:
                if queries_run > 0 and delay > 0:
                    time.sleep(delay)
                result, error = _run_query(session, _cfn_query(svc, ext), endpoint)
                queries_run += 1
                if error:
                    print(f"{prefix} cloudformation {ext_label} ERROR ({error})")
                    row["error"] = error
                    break
                mc, rc = result["match_count"], result["repo_count"]
                warn = " (shard limit -- count is a floor)" if result.get("limit_hit") else ""
                print(f"{prefix} cloudformation {ext_label} {mc} matches {rc} repos{warn}")
                cfn_match_total += mc
                for d in result.get("details", []):
                    repo = d.get("repo_url", "")
                    if repo:
                        cfn_repos.add(repo)
                    d["iac_type"] = "cloudformation"
                    d["filter"] = cfn_filter
                    all_details.append(d)

            if not row.get("error"):
                row["cfn_match_count"] = cfn_match_total
                row["cfn_repo_count"] = len(cfn_repos)

        rows.append(row)
        tracked[name] = row
        _save_tracking(tracking_path, tracked)

        if _is_complete(row):
            done += 1
        else:
            query_errors += 1

    incomplete = total - done
    print(f"\n{done}/{total} services complete ({done * 100 // total if total else 0}%)", end="")
    if incomplete:
        print(f", {incomplete} incomplete (rerun to retry)")
    print()

    return rows, all_details


def _analyze(cfn_types, tf_types, tf_to_service=None):
    if tf_to_service is None:
        tf_to_service = {}

    tf_counts = defaultdict(set)
    cfn_counts = defaultdict(set)

    for res in tf_types:
        parts = res.split("_")
        if len(parts) >= 2 and parts[0] == "aws":
            service = tf_to_service.get(res, parts[1].lower())
            tf_counts[service].add(res)

    for res in cfn_types:
        m = CFN_RE.match(res)
        if m:
            cfn_counts[m.group(1).lower()].add(res)

    result = {}
    for svc in set(tf_counts) | set(cfn_counts):
        tf_n = len(tf_counts.get(svc, ()))
        cfn_n = len(cfn_counts.get(svc, ()))
        result[svc] = {
            "tf_resource_count": tf_n,
            "cfn_resource_count": cfn_n,
            "combined_resource_count": tf_n + cfn_n,
        }
    return result


_CAMEL_RE1 = re.compile(r'([A-Z]+)([A-Z][a-z])')
_CAMEL_RE2 = re.compile(r'([a-z0-9])([A-Z])')


def _camel_to_snake(s):
    s = _CAMEL_RE1.sub(r'\1_\2', s)
    s = _CAMEL_RE2.sub(r'\1_\2', s)
    return s.lower()


def _build_map_candidates(parts):
    name_joined = "_".join(parts).lower()
    candidates = [name_joined]
    candidates.append("_".join(
        parts[:1] + re.findall('[A-Z][^A-Z]*', parts[1]) + parts[2:]
    ).lower())
    candidates.append("_".join(
        parts[:2] + re.findall('[A-Z][^A-Z]*', parts[2])
    ).lower())
    candidates.append("_".join(
        parts[:1] + re.findall('[A-Z][^A-Z]*', parts[1]) +
        re.findall('[A-Z][^A-Z]*', parts[2])
    ).lower())
    return name_joined, candidates


def _build_map(cfn_types, tf_types, min_ratio=0.50):
    tf_pool = list(tf_types)
    matched = set()
    results = []
    ratio = 1.0
    pass_n = 1

    while ratio >= min_ratio:
        before = len(results)
        for cfn_res in cfn_types:
            if cfn_res in matched:
                continue
            parts = cfn_res.split("::")
            if len(parts) < 3:
                continue

            name_joined, candidates = _build_map_candidates(parts)

            prefix_original = name_joined[:6]
            res_snake = _camel_to_snake(parts[2])
            prefix_resource = ("aws_" + res_snake)[:6]
            prefixes = {prefix_original, prefix_resource}

            for tf_res in tf_pool:
                if not any(tf_res.startswith(p) for p in prefixes):
                    continue
                best = max(SequenceMatcher(None, c, tf_res).ratio() for c in candidates)
                if best >= ratio:
                    results.append((tf_res, cfn_res, round(best, 3)))
                    matched.add(cfn_res)
                    tf_pool.remove(tf_res)
                    break

        new = len(results) - before
        pct = (len(results) / len(cfn_types) * 100) if cfn_types else 0
        log.debug("[%.2f] Pass %d: %d new, %d total (%.1f%%)", ratio, pass_n, new, len(results), pct)
        pass_n += 1
        ratio -= 0.01

    fallback_floor = max(min_ratio, 0.60)
    before_fallback = len(results)
    for cfn_res in cfn_types:
        if cfn_res in matched:
            continue
        parts = cfn_res.split("::")
        if len(parts) < 3:
            continue
        _, candidates = _build_map_candidates(parts)
        best_score = 0
        best_tf = None
        for tf_res in tf_pool:
            score = max(SequenceMatcher(None, c, tf_res).ratio() for c in candidates)
            if score > best_score:
                best_score = score
                best_tf = tf_res
        if best_tf and best_score >= fallback_floor:
            results.append((best_tf, cfn_res, round(best_score, 3)))
            matched.add(cfn_res)
            tf_pool.remove(best_tf)
    fallback_new = len(results) - before_fallback
    if fallback_new:
        log.debug("Fallback pass (no prefix filter, floor %.2f): %d new", fallback_floor, fallback_new)

    print(f"  {len(results)}/{len(cfn_types)} CFN resources mapped "
          f"({len(results) / len(cfn_types) * 100:.1f}%)")
    return results


def _mapping_to_tf_service(mapping):
    result = {}
    for tf_res, cfn_res, _score in mapping:
        m = CFN_RE.match(cfn_res)
        if m:
            result[tf_res] = m.group(1).lower()
    return result


# ---------------------------------------------------------------------------
# Resource type counting
# ---------------------------------------------------------------------------

def _extract_resource(match_text):
    m = _TF_RES_RE.search(match_text)
    if m:
        return m.group(1)
    m = _CFN_RES_RE.search(match_text)
    if m:
        return m.group(1)
    return "(unknown)"


def _normalize_cfn_type(cfn_type, cfn_to_tf):
    mapped = cfn_to_tf.get(cfn_type)
    if mapped:
        return mapped
    parts = cfn_type.split("::")
    if len(parts) == 3:
        return f"aws_{_camel_to_snake(parts[1])}_{_camel_to_snake(parts[2])}"
    return cfn_type.lower()


def _build_resource_counts(detail_rows, cfn_to_tf):
    counts = defaultdict(int)
    repos = defaultdict(set)
    for row in detail_rows:
        res = _extract_resource(row.get("match", ""))
        if res.startswith("AWS::"):
            res = _normalize_cfn_type(res, cfn_to_tf)
        counts[res] += 1
        repo = row.get("repo_url", "")
        if repo:
            repos[res].add(repo)

    rows = []
    for res, count in counts.items():
        rows.append({
            "resource_type": res,
            "match_count": count,
            "repo_count": len(repos[res]),
        })
    rows.sort(key=lambda r: -r["match_count"])
    return rows


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sg_query.py",
        description="Sourcegraph AWS resource frequency pipeline.",
    )
    parser.add_argument("--output", default="sg_results.csv",
                        help="Output CSV (default: sg_results.csv)")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Seconds between queries (default: 2.0)")
    parser.add_argument("--service", action="append",
                        help="Restrict to service(s); repeatable.")
    parser.add_argument("--endpoint", default=ENDPOINT,
                        help="Sourcegraph API endpoint override.")
    parser.add_argument("--min-ratio", type=float, default=0.50,
                        help="Build-map min similarity (default: 0.50)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if args.debug else logging.INFO,
        stream=sys.stderr,
    )

    _require_requests()
    token = _get_token()

    # --- Fetch resource types ---
    cfn_types, tf_types = _fetch_all_types()

    # --- Filter types to requested services before expensive mapping ---
    if args.service:
        wanted = {s.lower() for s in args.service}
        cfn_types = [t for t in cfn_types
                     if (m := CFN_RE.match(t)) and m.group(1).lower() in wanted]
        tf_types = [t for t in tf_types
                    if t.split("_")[1].lower() in wanted
                    and len(t.split("_")) >= 2 and t.startswith("aws_")]
        if not cfn_types and not tf_types:
            sys.exit("ERROR: no matching resource types for requested services.")

    # --- CFN-to-TF mapping (informs catalog + analysis) ---
    print("=== CFN-to-TF mapping ===")
    mapping = _build_map(cfn_types, tf_types, args.min_ratio)
    tf_to_service = _mapping_to_tf_service(mapping)
    print()

    # --- Build catalog using mapping ---
    catalog = _derive_catalog(cfn_types, tf_types, tf_to_service)

    # --- Load tracking file, query services ---
    tracked = _load_tracking(TRACKING_FILE)
    if tracked:
        catalog_names = {s["name"] for s in catalog}
        stale = set(tracked.keys()) - catalog_names
        if stale:
            log.info("Tracking file has %d stale service keys (catalog changed); "
                     "those services will be re-queried", len(stale))
        cached = sum(1 for s in catalog if _is_complete(tracked.get(s["name"], {})))
        print(f"Tracking file found: {cached}/{len(catalog)} services already complete\n")

    print("=== Per-service frequency ===")
    session = _build_session(token)
    freq_rows, detail_rows = _query_services(catalog, session, args.delay, args.endpoint, tracked, TRACKING_FILE)

    # --- Surface-area analysis ---
    print("=== Surface-area analysis ===")
    surface = _analyze(cfn_types, tf_types, tf_to_service)
    print(f"  {len(surface)} services with resource types\n")

    # --- Merge and write output ---
    print(f"\n=== Output ===")

    for row in freq_rows:
        sa = surface.get(row["service"], {})
        row["tf_resource_count"] = sa.get("tf_resource_count", 0)
        row["cfn_resource_count"] = sa.get("cfn_resource_count", 0)
        row["combined_resource_count"] = sa.get("combined_resource_count", 0)

    with open(args.output, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=MERGED_FIELDS)
        w.writeheader()
        w.writerows(freq_rows)
    print(f"Written to {args.output} ({len(freq_rows)} rows)")

    data_output = os.path.join(os.path.dirname(args.output) or ".", "sg_query_data.csv")
    with open(data_output, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=DATA_FIELDS)
        w.writeheader()
        w.writerows(detail_rows)
    print(f"Written to {data_output} ({len(detail_rows)} rows)")

    map_output = os.path.join(os.path.dirname(args.output) or ".", "sg_results_map.csv")
    with open(map_output, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=MAP_FIELDS)
        w.writeheader()
        for tf_res, cfn_res, score in mapping:
            m = CFN_RE.match(cfn_res)
            service = m.group(1).lower() if m else ""
            w.writerow({"tf_resource": tf_res, "cfn_resource": cfn_res,
                         "similarity": score, "service": service})
    print(f"Written to {map_output} ({len(mapping)} rows)")

    cfn_to_tf = {cfn_res: tf_res for tf_res, cfn_res, _ in mapping}
    rc_rows = _build_resource_counts(detail_rows, cfn_to_tf)
    rc_output = os.path.join(os.path.dirname(args.output) or ".", "sg_resource_counts.csv")
    with open(rc_output, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=RESOURCE_COUNT_FIELDS)
        w.writeheader()
        w.writerows(rc_rows)
    print(f"Written to {rc_output} ({len(rc_rows)} resource types)")

    # --- Cleanup tracking if everything completed ---
    incomplete = sum(1 for r in freq_rows if not _is_complete(r))
    if incomplete:
        print(f"\n  {incomplete} services incomplete -- rerun to retry")
    else:
        if os.path.exists(TRACKING_FILE):
            os.remove(TRACKING_FILE)
        print(f"\n  All services complete -- tracking file removed")


if __name__ == "__main__":
    main()
