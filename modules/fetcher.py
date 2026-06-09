import json


def _safe_dict(obj):
    """Convert SDK object to plain dict safely."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return {}


def _extract_effect(policy_rule) -> str:
    if not policy_rule:
        return "Unknown"
    rule = policy_rule if isinstance(policy_rule, dict) else {}
    then = rule.get("then", {})
    if not isinstance(then, dict):
        return "Unknown"
    effect = then.get("effect", "")
    if isinstance(effect, str):
        # Could be a parameter reference like "[parameters('effect')]"
        if effect.startswith("[") and "parameters" in effect:
            return "Parameterized"
        return effect or "Unknown"
    return "Unknown"


class PolicyFetcher:
    """Fetches policy definitions, assignments, and compliance data from Azure."""

    def __init__(self, credential):
        self.credential = credential

    def get_compliance_summary(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient
            client = PolicyInsightsClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            result = client.policy_states.summarize_for_subscription(
                policy_states_summary_resource="latest",
            )
            items = []
            for summary in (result.value or []):
                for pa in (summary.policy_assignments or []):
                    r = pa.results
                    non_compliant = getattr(r, "non_compliant_resources", 0) or 0
                    if non_compliant > 0:
                        pa_id = pa.policy_assignment_id or ""
                        items.append({
                            "policy_assignment_id": pa_id,
                            "policy_assignment_name": pa_id.split("/")[-1] if pa_id else "Unknown",
                            "non_compliant_resources": non_compliant,
                            "non_compliant_policies": getattr(r, "non_compliant_policies", 0) or 0,
                        })
            items.sort(key=lambda x: x["non_compliant_resources"], reverse=True)
            return items
        except Exception as e:
            print(f"  [warn] compliance summary failed: {e}")
            return []

    def get_custom_policies(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            client = PolicyClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            policies = []
            for p in client.policy_definitions.list():
                pt = p.policy_type
                if hasattr(pt, "value"):
                    pt = pt.value
                if str(pt) != "Custom":
                    continue
                meta = _safe_dict(p.metadata)
                rule = _safe_dict(p.policy_rule)
                policies.append({
                    "id": p.id or "",
                    "name": p.name or "",
                    "display_name": p.display_name or p.name or "",
                    "description": p.description or "",
                    "category": meta.get("category", "") if meta else "",
                    "mode": p.mode or "",
                    "effect": _extract_effect(rule),
                    "policy_rule": rule,
                    "metadata": meta,
                    "version": meta.get("version", "") if meta else "",
                })
            return policies
        except Exception as e:
            print(f"  [warn] custom policy fetch failed: {e}")
            return []

    def get_policy_assignments(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            client = PolicyClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            assignments = []
            for a in client.policy_assignments.list():
                assignments.append({
                    "id": a.id or "",
                    "name": a.name or "",
                    "policy_definition_id": a.policy_definition_id or "",
                    "scope": a.scope or "",
                    "display_name": a.display_name or a.name or "",
                })
            return assignments
        except Exception as e:
            print(f"  [warn] assignments fetch failed: {e}")
            return []

    def get_builtin_policies(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            client = PolicyClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            policies = []
            for p in client.policy_definitions.list_built_in():
                meta = _safe_dict(p.metadata)
                rule = _safe_dict(p.policy_rule)
                policies.append({
                    "id": p.id or "",
                    "name": p.name or "",
                    "display_name": p.display_name or p.name or "",
                    "description": p.description or "",
                    "category": meta.get("category", "") if meta else "",
                    "effect": _extract_effect(rule),
                })
            return policies
        except Exception as e:
            print(f"  [warn] built-in policy fetch failed: {e}")
            return []
