


"""
Fetches all Azure built-in policy definitions and saves them to data/builtin-policies.json.
Runs inside GitHub Actions with a Service Principal.

Required environment variables:
  AZURE_TENANT_ID
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET
  AZURE_SUBSCRIPTION_ID
"""

import json
import os
import time

from azure.identity import ClientSecretCredential
from azure.mgmt.resource import PolicyClient


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

    print("Fetching built-in policy definitions...")
    policies = []
    for p in client.policy_definitions.list(filter="policyType eq 'BuiltIn'"):
        meta = safe_dict(getattr(p, "metadata", None))
        rule = safe_dict(p.policy_rule)
        policies.append({
            "id": p.id or "",
            "name": p.name or "",
            "display_name": p.display_name or p.name or "",
            "description": p.description or "",
            "category": meta.get("category", "") if meta else "",
            "effect": extract_effect(rule),
        })

    os.makedirs("data", exist_ok=True)
    with open("data/builtin-policies.json", "w", encoding="utf-8") as f:
        json.dump(policies, f, ensure_ascii=False)

    with open("data/cache-meta.json", "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": time.time(),
            "updated_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(policies),
            "source": "github-actions",
        }, f)

    print(f"Saved {len(policies)} built-in policies to data/builtin-policies.json")


if __name__ == "__main__":
    main()
