"""
Fetches all Azure built-in policy definitions, extracts semantic fingerprints,
and saves to data/builtin-policies.json.
Runs inside GitHub Actions with a Service Principal.

Required environment variables:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID
"""

import json, os, time, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from azure.identity import ClientSecretCredential
from azure.mgmt.resource import PolicyClient
from modules.recommender import _extract_operation


def safe_dict(obj):
    if not obj:
        return {}
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return {}


def extract_effect(rule: dict) -> str:
    try:
        then = rule.get("then", {})
        effect = then.get("effect", "") if isinstance(then, dict) else ""
        if isinstance(effect, str):
            if effect.startswith("[") and "parameters" in effect:
                return "Parameterized"
            return effect or "Unknown"
    except Exception:
        pass
    return "Unknown"


def main():
    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    sub_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    client = PolicyClient(credential=credential, subscription_id=sub_id)

    print("Fetching built-in policy definitions + extracting semantic fingerprints...")
    policies = []
    for i, p in enumerate(client.policy_definitions.list_built_in()):
        meta = safe_dict(p.metadata)
        rule = safe_dict(p.policy_rule)
        effect = extract_effect(rule)

        # Extract semantic fingerprint
        op = _extract_operation(rule)

        entry = {
            "id": p.id or "",
            "name": p.name or "",
            "display_name": p.display_name or p.name or "",
            "description": p.description or "",
            "category": meta.get("category", "") if meta else "",
            "effect": effect,
            # Semantic fingerprint
            "operation": op["operation"],
            "resource_types": list(op["resource_types"]),
        }
        policies.append(entry)
        if (i + 1) % 100 == 0:
            print(f"  Processed {i+1} policies...")

    os.makedirs("data", exist_ok=True)
    with open("data/builtin-policies.json", "w", encoding="utf-8") as f:
        json.dump(policies, f, ensure_ascii=False)

    with open("data/cache-meta.json", "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": time.time(),
            "updated_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(policies),
            "source": "github-actions",
            "has_fingerprints": True,
        }, f)

    # Print operation distribution for visibility
    from collections import Counter
    ops = Counter(p["operation"] for p in policies)
    print(f"\nSaved {len(policies)} built-in policies with fingerprints")
    print("Operation distribution:")
    for op_name, count in ops.most_common(15):
        print(f"  {op_name}: {count}")


if __name__ == "__main__":
    main()
