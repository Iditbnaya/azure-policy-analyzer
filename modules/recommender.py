"""
Semantic policy recommender.

Instead of keyword matching on names, this analyzes what the custom policy
actually DOES (resource type, field, effect, operation) and finds built-ins
that perform the same operation.
"""

import json
import re
from difflib import SequenceMatcher


# -----------------------------------------------------------------------
# Policy rule semantic extractor
# -----------------------------------------------------------------------

def _extract_resource_types(rule: dict) -> set:
    """Extract resource types from the if-block field conditions."""
    types = set()
    rule_str = json.dumps(rule)
    # field=type, equals=Microsoft.X/Y
    for match in re.findall(r'"Microsoft\.[A-Za-z]+/[A-Za-z]+"', rule_str):
        types.add(match.strip('"').lower())
    return types


def _extract_operation(rule: dict) -> dict:
    """
    Determine what the policy does:
    - operation: tag_inherit | tag_add | tag_require | diagnostic | deny_resource_type |
                 deny_property | audit_property | deploy | modify_property
    - target_field: the field being checked/modified
    - resource_types: set of resource types targeted
    - effect: policy effect
    """
    op = {
        "operation": "unknown",
        "target_field": "",
        "resource_types": set(),
        "effect": "unknown",
        "scope": "any",
        "details": {},
    }

    if not rule or not isinstance(rule, dict):
        return op

    rule_str = json.dumps(rule).lower()
    then = rule.get("then", {}) or {}
    if_block = rule.get("if", {}) or {}

    # Effect
    effect_raw = ""
    if isinstance(then, dict):
        effect_raw = str(then.get("effect", "")).lower()
    if "parameters" in effect_raw:
        # Parameterized - guess from deployment details
        if "deployifnotexists" in rule_str:
            effect_raw = "deployifnotexists"
        elif "modify" in rule_str:
            effect_raw = "modify"
        elif "deny" in rule_str[:200]:
            effect_raw = "deny"
        else:
            effect_raw = "audit"
    op["effect"] = effect_raw

    # Resource types
    op["resource_types"] = _extract_resource_types(rule)

    # Detect diagnostic settings
    if "microsoft.insights/diagnosticsettings" in rule_str:
        op["operation"] = "diagnostic_settings"
        return op

    # Detect tag operations
    if_str = json.dumps(if_block).lower()
    then_str = json.dumps(then).lower()
    if "tags[" in if_str or "tags[" in then_str or '"tags"' in if_str:
        details = then.get("details", {}) if isinstance(then, dict) else {}
        details_str = json.dumps(details).lower()
        ops_list = details.get("operations", []) if isinstance(details, dict) else []

        if "resourcegroup" in rule_str or "subscription" in rule_str:
            if "inherit" in rule_str or "addorreplace" in details_str:
                op["operation"] = "tag_inherit_from_rg" if "resourcegroup" in rule_str else "tag_inherit_from_subscription"
            else:
                op["operation"] = "tag_inherit_from_rg"
        elif "addifnotexists" in details_str or "addorreplace" in details_str:
            op["operation"] = "tag_add"
        elif effect_raw in ("deny",):
            op["operation"] = "tag_require"
        else:
            op["operation"] = "tag_audit"

        # Extract tag name
        tag_names = re.findall(r"tags\['([^']+)'\]", rule_str)
        if tag_names:
            op["details"]["tag_names"] = list(set(tag_names))
        return op

    # Detect VNet peering
    if "virtualnetworkpeerings" in rule_str or "vnet" in rule_str and "peering" in rule_str:
        op["operation"] = "vnet_peering_deny"
        return op

    # Detect location/allowed-locations
    if '"location"' in if_str and effect_raw in ("deny", "audit"):
        op["operation"] = "allowed_locations"
        return op

    # Detect storage/network access
    if "publicnetworkaccess" in rule_str or "networkacls" in rule_str:
        op["operation"] = "deny_public_access"
        return op

    # Detect TLS / HTTPS
    if "tls" in rule_str or "https" in rule_str or "minimumt" in rule_str:
        op["operation"] = "tls_enforcement"
        return op

    # Detect SKU restrictions
    if '"sku"' in rule_str and effect_raw in ("deny", "audit"):
        op["operation"] = "sku_restriction"
        return op

    # Detect UDR / route table
    if "routetable" in rule_str or "routes" in rule_str:
        op["operation"] = "udr_enforce"
        return op

    # Detect naming convention
    if "like" in rule_str or "match" in rule_str and "name" in if_str:
        op["operation"] = "naming_convention"
        return op

    # Fallback: deny or audit a property
    if effect_raw == "deny":
        op["operation"] = "deny_property"
    elif effect_raw in ("audit", "auditifnotexists"):
        op["operation"] = "audit_property"
    elif effect_raw == "deployifnotexists":
        op["operation"] = "deploy"
    elif effect_raw == "modify":
        op["operation"] = "modify_property"

    return op


# -----------------------------------------------------------------------
# Built-in semantic fingerprinting (from display name + description + category)
# -----------------------------------------------------------------------

OPERATION_KEYWORDS = {
    "tag_inherit_from_rg": [
        "inherit.*tag.*resource group", "tag.*resource group.*missing",
        "inherit tag from the resource group",
    ],
    "tag_inherit_from_subscription": [
        "inherit.*tag.*subscription", "tag.*subscription.*missing",
        "inherit tag from the subscription",
    ],
    "tag_add": [
        "add.*tag", "require.*tag", "append.*tag", "missing.*tag",
    ],
    "tag_require": [
        "require.*tag", "tag must", "enforce tag",
    ],
    "tag_audit": [
        "tag", "resources should have",
    ],
    "diagnostic_settings": [
        "diagnostic", "log analytics", "monitoring", "deploy.*diagnostic",
    ],
    "vnet_peering_deny": [
        "peering", "vnet peering", "virtual network peering",
    ],
    "allowed_locations": [
        "allowed location", "restrict location", "region restriction",
    ],
    "deny_public_access": [
        "public network access", "public endpoint", "disable public",
        "no public", "private endpoint",
    ],
    "tls_enforcement": [
        "tls", "https", "secure transfer", "minimum tls",
    ],
    "sku_restriction": [
        "sku", "allowed sku", "vm size", "restrict size",
    ],
    "udr_enforce": [
        "route table", "udr", "user.defined route", "next hop",
    ],
    "naming_convention": [
        "naming", "name.*convention", "name.*prefix", "name.*suffix",
    ],
    "deploy": [
        "deploy", "configure", "enable", "install",
    ],
    "modify_property": [
        "modify", "configure", "set.*property",
    ],
    "deny_property": [
        "deny", "not allowed", "prohibited", "prevent",
    ],
    "audit_property": [
        "audit", "should", "must", "compliance",
    ],
}


def _builtin_operation_score(builtin_text: str, operation: str) -> int:
    """Score how well a built-in's text matches an operation."""
    score = 0
    keywords = OPERATION_KEYWORDS.get(operation, [])
    text = builtin_text.lower()
    for kw in keywords:
        if re.search(kw, text):
            score += 25
    return min(score, 60)


# -----------------------------------------------------------------------
# Main recommender
# -----------------------------------------------------------------------

class PolicyRecommender:

    def get_recommendations(self, problematic_policies: list, builtin_policies: list) -> list:
        if not problematic_policies or not builtin_policies:
            return []

        recommendations = []
        for policy in problematic_policies:
            matches = self._find_matches(policy, builtin_policies)
            if matches:
                recommendations.append({
                    "custom_policy": {
                        "id": policy.get("id", ""),
                        "name": policy.get("name", ""),
                        "display_name": policy.get("display_name", ""),
                        "effect": policy.get("effect", ""),
                        "category": policy.get("category", ""),
                        "issue_count": policy.get("issue_count", 0),
                        "warning_count": policy.get("warning_count", 0),
                    },
                    "matches": matches[:5],
                })
        return recommendations

    def _find_matches(self, custom: dict, builtins: list) -> list:
        # Extract semantic operation from the policy rule
        rule = custom.get("policy_rule") or {}
        op = _extract_operation(rule)
        operation = op["operation"]
        resource_types = op["resource_types"]
        custom_effect = op["effect"]

        c_name = custom.get("display_name", "").lower()
        c_desc = custom.get("description", "").lower()
        c_cat = custom.get("category", "").lower()
        c_text = c_name + " " + c_desc

        scored = []
        for b in builtins:
            score = 0
            b_name = b.get("display_name", "").lower()
            b_desc = b.get("description", "").lower()
            b_cat = b.get("category", "").lower()
            b_effect = b.get("effect", "").lower()
            b_text = b_name + " " + b_desc

            # 1. Operation match (semantic - highest weight)
            if operation != "unknown":
                op_score = _builtin_operation_score(b_text, operation)
                score += op_score

            # 2. Effect match
            if custom_effect and custom_effect not in ("parameterized", "unknown"):
                if custom_effect == b_effect or custom_effect == b_effect.replace("ifnotexists", ""):
                    score += 20
                elif b_effect == "parameterized" or not b_effect:
                    score += 5

            # 3. Resource type match (check built-in name/desc mentions the resource type)
            if resource_types:
                for rt in resource_types:
                    # e.g. "microsoft.keyvault/vaults" -> check for "key vault" in built-in
                    rt_short = rt.split("/")[-1].lower()  # "vaults"
                    rt_service = rt.split("/")[0].replace("microsoft.", "").lower()  # "keyvault"
                    # also try spaced version: "keyvault" -> "key vault"
                    rt_spaced = re.sub(r'([a-z])([A-Z])', r'\1 \2',
                                       rt.split("/")[-1]).lower()
                    if rt_short in b_text or rt_service in b_text or rt_spaced in b_text:
                        score += 25

            # 4. Category match
            if c_cat and b_cat:
                if c_cat == b_cat:
                    score += 15
                elif c_cat in b_cat or b_cat in c_cat:
                    score += 7

            # 5. Name similarity (lower weight - names can be misleading)
            if c_name and b_name:
                sim = SequenceMatcher(None, c_name, b_name).ratio()
                score += int(sim * 15)

            # Minimum threshold
            if score >= 35:
                scored.append({
                    **b,
                    "match_score": min(98, score),
                    "match_reason": self._explain(op, custom, b, score),
                })

        # Sort by score, deduplicate
        scored.sort(key=lambda x: x["match_score"], reverse=True)

        # Remove obvious wrong-scope suggestions:
        # If operation is tag_inherit_from_rg, demote "from subscription" matches
        if operation == "tag_inherit_from_rg":
            scored = [b for b in scored
                      if "subscription" not in b.get("display_name", "").lower()
                      or b["match_score"] < 60]

        if operation == "tag_inherit_from_subscription":
            scored = [b for b in scored
                      if "resource group" not in b.get("display_name", "").lower()
                      or b["match_score"] < 60]

        return scored[:5]

    def _explain(self, op: dict, custom: dict, builtin: dict, score: int) -> str:
        reasons = []
        op_name = op.get("operation", "unknown")

        if op_name != "unknown":
            label = op_name.replace("_", " ").title()
            reasons.append(f"Same operation: {label}")

        c_eff = op.get("effect", "")
        b_eff = builtin.get("effect", "").lower()
        if c_eff and b_eff and c_eff == b_eff:
            reasons.append(f"Same effect: {builtin.get('effect', '')}")

        if custom.get("category", "").lower() == builtin.get("category", "").lower() and custom.get("category"):
            reasons.append(f"Same category: {builtin.get('category', '')}")

        if op.get("resource_types"):
            reasons.append(f"Targets same resource type")

        if not reasons:
            reasons.append("Keyword and description similarity")

        return "; ".join(reasons)
