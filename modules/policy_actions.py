"""
Azure Policy write operations with danger assessment.
Every function returns a plain dict result.
"""

import json
import uuid


DANGER_EFFECTS = {"deny", "denyaction"}


def _scope_breadth(scope: str) -> str:
    s = (scope or "").lower()
    if "managementgroups" in s:
        return "management_group"
    if s.startswith("/subscriptions/") and s.count("/") <= 3:
        return "subscription"
    return "resource_group_or_lower"


def assess_danger(effect: str, scope: str, resource_count: int = 0) -> tuple:
    """Returns (level: str, reasons: list[str])  level in SAFE / WARNING / DANGER."""
    level = "SAFE"
    reasons = []

    effect_lc = (effect or "").lower()
    if effect_lc in DANGER_EFFECTS:
        level = "DANGER"
        reasons.append(
            f"Effect '{effect}' will BLOCK all non-compliant resources immediately"
        )

    breadth = _scope_breadth(scope)
    if breadth == "management_group":
        if level != "DANGER":
            level = "DANGER"
        reasons.append("Assignment targets a Management Group - affects ALL child subscriptions")
    elif breadth == "subscription":
        if level not in ("DANGER",):
            level = "WARNING"
        reasons.append("Assignment targets an entire subscription")

    if resource_count > 100:
        level = "DANGER"
        reasons.append(f"Remediation will modify {resource_count} resources")
    elif resource_count > 10:
        if level == "SAFE":
            level = "WARNING"
        reasons.append(f"Remediation will affect {resource_count} resources")

    if not reasons:
        reasons.append("Low-risk operation")

    return level, reasons


def assign_policy(credential, subscription_id: str, policy_definition_id: str,
                  scope: str, display_name: str, parameters: dict = None,
                  enforcement_mode: str = "Default",
                  needs_identity: bool = False, location: str = "westeurope") -> dict:
    from azure.mgmt.resource import PolicyClient
    client = PolicyClient(credential=credential, subscription_id=subscription_id)
    name = "apa-" + str(uuid.uuid4())[:8]
    props = {
        "policy_definition_id": policy_definition_id,
        "display_name": display_name,
        "enforcement_mode": enforcement_mode,
    }
    if parameters:
        props["parameters"] = {k: {"value": v} for k, v in parameters.items()}
    if needs_identity:
        props["location"] = location
        props["identity"] = {"type": "SystemAssigned"}
    result = client.policy_assignments.create(scope, name, props)
    return {
        "id": result.id,
        "name": result.name,
        "scope": result.scope,
        "policy_definition_id": result.policy_definition_id,
        "identity_assigned": needs_identity,
    }


def create_custom_policy(credential, subscription_id: str, definition: dict) -> dict:
    from azure.mgmt.resource import PolicyClient
    client = PolicyClient(credential=credential, subscription_id=subscription_id)
    props_src = definition.get("properties", definition)
    name = definition.get("name") or "apa-custom-" + str(uuid.uuid4())[:8]
    props = {
        "policy_type": "Custom",
        "display_name": props_src.get("displayName") or props_src.get("display_name", name),
        "description": props_src.get("description", ""),
        "policy_rule": props_src.get("policyRule") or props_src.get("policy_rule", {}),
        "parameters": props_src.get("parameters", {}),
        "metadata": props_src.get("metadata", {"category": "Custom"}),
        "mode": props_src.get("mode", "All"),
    }
    result = client.policy_definitions.create_or_update(name, props)
    return {"id": result.id, "name": result.name, "display_name": result.display_name}


def trigger_remediation(credential, subscription_id: str, assignment_id: str) -> dict:
    from azure.mgmt.policyinsights import PolicyInsightsClient
    client = PolicyInsightsClient(credential=credential, subscription_id=subscription_id)
    task_name = "rem-" + str(uuid.uuid4())[:8]
    result = client.remediations.create_or_update_at_subscription(
        task_name,
        {"policy_assignment_id": assignment_id},
    )
    return {
        "id": result.id,
        "name": result.name,
        "provisioning_state": result.provisioning_state,
    }


def delete_assignment(credential, subscription_id: str, scope: str,
                      assignment_name: str) -> bool:
    from azure.mgmt.resource import PolicyClient
    client = PolicyClient(credential=credential, subscription_id=subscription_id)
    client.policy_assignments.delete(scope, assignment_name)
    return True
