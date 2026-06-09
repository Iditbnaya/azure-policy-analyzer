"""
Built-in policy cache manager.

Priority order for getting built-in policies:
  1. Local cache (if < 24h old)
  2. Remote download from GitHub raw URL (always fresh)
  3. Live Azure API call
  4. Stale local cache (last resort)
"""

import json
import time
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
CACHE_FILE = DATA_DIR / "builtin-policies.json"
META_FILE = DATA_DIR / "cache-meta.json"
REMOTE_URL = (
    "https://raw.githubusercontent.com/Iditbnaya/azure-policy-analyzer"
    "/master/data/builtin-policies.json"
)
CACHE_MAX_AGE_H = 24


def _ensure_dir():
    DATA_DIR.mkdir(exist_ok=True)


def get_meta() -> dict:
    if META_FILE.exists():
        try:
            return json.loads(META_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def cache_age_hours() -> float:
    meta = get_meta()
    if "updated_at" not in meta:
        return float("inf")
    return (time.time() - meta["updated_at"]) / 3600


def load_local() -> list:
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def save(policies: list, source: str = "unknown"):
    _ensure_dir()
    CACHE_FILE.write_text(
        json.dumps(policies, ensure_ascii=False), encoding="utf-8"
    )
    META_FILE.write_text(
        json.dumps({
            "updated_at": time.time(),
            "updated_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(policies),
            "source": source,
        }),
        encoding="utf-8",
    )


def try_download_remote() -> list:
    try:
        req = urllib.request.Request(
            REMOTE_URL, headers={"User-Agent": "azure-policy-analyzer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
            if isinstance(data, list) and len(data) > 100:
                print(f"  [cache] downloaded {len(data)} built-ins from GitHub")
                return data
    except Exception as e:
        print(f"  [cache] remote download failed: {e}")
    return []


def get(credential=None, subscription_id: str = None, force: bool = False) -> tuple:
    """
    Returns (policies: list, source: str).
    source: 'cache' | 'remote' | 'azure' | 'stale' | 'empty'
    """
    age = cache_age_hours()

    if not force and age < CACHE_MAX_AGE_H:
        local = load_local()
        if local:
            return local, "cache"

    remote = try_download_remote()
    if remote:
        save(remote, "remote")
        return remote, "remote"

    if credential and subscription_id:
        print("  [cache] fetching built-ins from Azure API (this takes ~30s)...")
        from modules.fetcher import PolicyFetcher
        fetcher = PolicyFetcher(credential)
        policies = fetcher.get_builtin_policies(subscription_id)
        if policies:
            save(policies, "azure")
            return policies, "azure"

    local = load_local()
    return (local, "stale") if local else ([], "empty")
