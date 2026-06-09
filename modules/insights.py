"""
Insights analyzer: detects duplicate policies, deprecated assignments,
and initiative consolidation opportunities.
"""

from collections import defaultdict


def find_duplicate_policies(custom_policies: list, assignments: list) -> list:
    """
    Find scopes where multiple policies do the same thing (same operation + resource_types).
    Returns list of duplicate groups.
    """
    # Build fingerprint map: (operation, frozenset(resource_types)) -> [policies]
    fingerprint_map = defaultdict(list)
    for p in custom_policies:
        op = p.get("operation", "unknown")
        rts = frozenset(p.get("resource_types", []))
        if op == "unknown":
            continue
        fingerprint_map[(op, rts)].append(p)

    # Build assignment lookup: policy_name -> scopes
    assign_lookup = defaultdict(list)
    for a in assignments:
        pid = a.get("policy_definition_id", "")
        name = pid.rstrip("/").split("/")[-1]
        assign_lookup[name].append(a.get("scope", ""))

    duplicates = []
    seen = set()
    for (op, rts), policies in fingerprint_map.items():
        if len(policies) < 2:
            continue
        key = (op, rts)
        if key in seen:
            continue
        seen.add(key)

        # Check if they share any common scope
        scope_policy_map = defaultdict(list)
        for p in policies:
            scopes = assign_lookup.get(p.get("name", ""), [])
            for s in scopes:
                scope_policy_map[s].append(p)
            if not scopes:
                scope_policy_map["__unassigned__"].append(p)

        # Report scopes with 2+ policies doing the same thing
        for scope, scope_policies in scope_policy_map.items():
            if len(scope_policies) >= 2:
                duplicates.append({
                    "operation": op,
                    "resource_types": list(rts),
                    "scope": scope,
                    "policies": [
                        {
                            "name": p.get("name", ""),
                            "display_name": p.get("display_name", ""),
                            "effect": p.get("effect", ""),
                        }
                        for p in scope_policies
                    ],
                    "recommendation": f"Keep the most complete definition and remove the others. Consider replacing all with a single built-in policy.",
                })

        # Also report if all policies have no scope overlap but exist for same purpose
        if not any(len(v) >= 2 for v in scope_policy_map.values()) and len(policies) >= 2:
            duplicates.append({
                "operation": op,
                "resource_types": list(rts),
                "scope": None,
                "policies": [
                    {
                        "name": p.get("name", ""),
                        "display_name": p.get("display_name", ""),
                        "effect": p.get("effect", ""),
                    }
                    for p in policies
                ],
                "recommendation": "These policies do the same thing but are assigned to different scopes. Consider consolidating into one policy with a broader scope, or replacing with a single built-in.",
            })

    return duplicates


def find_deprecated_assignments(custom_policies: list, builtin_policies: list,
                                assignments: list) -> list:
    """
    Find policy assignments where:
    1. The custom policy definition is marked as deprecated
    2. The policy references a deprecated built-in
    3. The assignment references a policy that no longer exists (broken reference)
    """
    # Build lookup maps
    custom_by_name = {p["name"]: p for p in custom_policies}
    builtin_by_name = {b["name"]: b for b in builtin_policies}
    all_def_names = set(custom_by_name.keys()) | set(builtin_by_name.keys())

    results = []
    for a in assignments:
        pid = a.get("policy_definition_id", "")
        pname = pid.rstrip("/").split("/")[-1]
        display = a.get("display_name") or pname

        # Check broken reference
        if pname and pname not in all_def_names:
            results.append({
                "type": "broken_reference",
                "severity": "error",
                "assignment_name": display,
                "assignment_id": a.get("id", ""),
                "scope": a.get("scope", ""),
                "policy_name": pname,
                "message": f"Policy definition '{pname}' no longer exists",
                "recommendation": "Remove this assignment - it references a deleted policy definition and will always show as non-compliant.",
            })
            continue

        # Check custom deprecated
        if pname in custom_by_name:
            p = custom_by_name[pname]
            if p.get("deprecated"):
                results.append({
                    "type": "deprecated_custom",
                    "severity": "warning",
                    "assignment_name": display,
                    "assignment_id": a.get("id", ""),
                    "scope": a.get("scope", ""),
                    "policy_name": pname,
                    "message": f"Custom policy '{p.get('display_name', pname)}' is marked as deprecated",
                    "recommendation": "Replace with a current policy or the built-in equivalent.",
                })

    return results


def find_initiative_opportunities(custom_policies: list, assignments: list,
                                  builtin_policies: list) -> list:
    """
    Find groups of custom policies that could be replaced by a single built-in initiative.
    Groups custom policies by operation type and checks for initiative-level coverage.
    """
    from collections import Counter

    # Group assigned custom policies by operation
    assigned_names = {
        a.get("policy_definition_id", "").rstrip("/").split("/")[-1]
        for a in assignments
    }

    by_operation = defaultdict(list)
    for p in custom_policies:
        if p.get("name") in assigned_names:
            op = p.get("operation", "unknown")
            if op != "unknown":
                by_operation[op].append(p)

    # Group by category too
    by_category = defaultdict(list)
    for p in custom_policies:
        if p.get("name") in assigned_names:
            cat = p.get("category", "").strip()
            if cat:
                by_category[cat].append(p)

    opportunities = []

    # Diagnostic settings - very common initiative opportunity
    diag_policies = by_operation.get("diagnostic_settings", [])
    if len(diag_policies) >= 3:
        opportunities.append({
            "type": "diagnostic_settings_initiative",
            "severity": "high",
            "title": "Replace diagnostic settings policies with built-in initiative",
            "affected_count": len(diag_policies),
            "affected_policies": [{"name": p["name"], "display_name": p["display_name"]} for p in diag_policies[:10]],
            "recommendation": (
                f"You have {len(diag_policies)} custom diagnostic settings policies. "
                "The built-in initiative 'Enable Azure Monitor for VMs' or 'Deploy Diagnostic Settings to Log Analytics' "
                "covers these automatically and updates when new Azure resource types are added."
            ),
            "builtin_initiative_search": "diagnostic settings log analytics",
            "portal_url": "https://portal.azure.com/#view/Microsoft_Azure_Policy/InitiativesMenuBlade",
        })

    # TLS enforcement
    tls_policies = by_operation.get("tls_enforcement", [])
    if len(tls_policies) >= 2:
        opportunities.append({
            "type": "tls_initiative",
            "severity": "medium",
            "title": "Consolidate TLS/HTTPS enforcement policies",
            "affected_count": len(tls_policies),
            "affected_policies": [{"name": p["name"], "display_name": p["display_name"]} for p in tls_policies[:10]],
            "recommendation": (
                f"You have {len(tls_policies)} custom TLS/HTTPS policies for different resource types. "
                "Consider using the Azure Security Benchmark or CIS initiative which includes "
                "TLS enforcement for all resource types in one assignment."
            ),
            "portal_url": "https://portal.azure.com/#view/Microsoft_Azure_Policy/InitiativesMenuBlade",
        })

    # Deny public access
    public_access = by_operation.get("deny_public_access", [])
    if len(public_access) >= 2:
        opportunities.append({
            "type": "public_access_initiative",
            "severity": "medium",
            "title": "Consolidate public network access policies",
            "affected_count": len(public_access),
            "affected_policies": [{"name": p["name"], "display_name": p["display_name"]} for p in public_access[:10]],
            "recommendation": (
                f"You have {len(public_access)} custom 'deny public access' policies. "
                "The built-in initiative 'Deny or Audit resources without Public Network Access' "
                "covers all resource types in a single assignment."
            ),
            "portal_url": "https://portal.azure.com/#view/Microsoft_Azure_Policy/InitiativesMenuBlade",
        })

    # Category-level groupings (3+ policies in same category with no initiative yet)
    for cat, cat_policies in by_category.items():
        if len(cat_policies) >= 4:
            # Only suggest if not already covered above
            cat_ops = {p.get("operation") for p in cat_policies}
            if "diagnostic_settings" in cat_ops and len(diag_policies) >= 3:
                continue
            opportunities.append({
                "type": "category_initiative",
                "severity": "low",
                "title": f"Consider a '{cat}' initiative for {len(cat_policies)} policies",
                "affected_count": len(cat_policies),
                "affected_policies": [{"name": p["name"], "display_name": p["display_name"]} for p in cat_policies[:8]],
                "recommendation": (
                    f"You have {len(cat_policies)} custom policies in the '{cat}' category. "
                    f"Search for a built-in initiative covering '{cat}' compliance to replace them all."
                ),
                "portal_url": f"https://portal.azure.com/#view/Microsoft_Azure_Policy/InitiativesMenuBlade",
            })

    # Sort by affected_count desc
    opportunities.sort(key=lambda x: x["affected_count"], reverse=True)
    return opportunities
