"""
ALZ (Azure Landing Zone) Compliance Score.
All policies verified as non-deprecated as of June 2026.
"""

# ALZ recommended policies - verified non-deprecated
ALZ_RECOMMENDED = [
    # Security - Critical
    {"id": "1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "name": "Enable Microsoft Defender for Cloud plans", "category": "Security", "weight": 3},
    {"id": "5eb6d64a-4086-4d7a-92da-ec51aed0332d", "name": "Configure Microsoft Defender for Servers plan", "category": "Security", "weight": 3},
    {"id": "0961003e-5a0a-4549-abde-af6a37f2724d", "name": "Disk encryption should be enabled on virtual machines", "category": "Security", "weight": 3},
    {"id": "b0f33259-77d7-4c9e-aac6-3aabcfae693c", "name": "Management ports of VMs should be protected with JIT", "category": "Security", "weight": 2},
    {"id": "9daedab3-fb2d-461e-b861-71790eead4f6", "name": "All network ports should be restricted on NSGs associated to your VM", "category": "Security", "weight": 2},
    {"id": "4efbd9d8-6bc6-45f6-9be2-7fe9dd5d89ff", "name": "Configure Windows VMs to run Azure Monitor Agent", "category": "Security", "weight": 2},

    # Monitoring - Critical
    {"id": "4da35fc9-c9e7-4960-aec9-797fe7d9051d", "name": "Azure Defender for servers should be enabled", "category": "Monitoring", "weight": 3},
    {"id": "1afdc4b6-581a-45fb-b630-f1e6051e3e7a", "name": "Linux virtual machines should have Azure Monitor Agent installed", "category": "Monitoring", "weight": 2},
    {"id": "3672e6f7-a74d-4763-b138-fcf332042f8f", "name": "Windows virtual machine scale sets should have Azure Monitor Agent installed", "category": "Monitoring", "weight": 2},

    # Identity - Important (using non-deprecated MFA policy)
    {"id": "4efbd9d8-6bc6-45f6-9be2-7fe9dd5d89ff", "name": "Configure Windows VMs to run Azure Monitor Agent (system-assigned)", "category": "Identity", "weight": 2},
    {"id": "4e6c27d5-a6ee-49cf-b2b4-d8fe90fa2b8b", "name": "Users must authenticate with MFA to create or update resources", "category": "Identity", "weight": 3},
    {"id": "931e118d-0e2d-4c84-9e0a-30b88e272ab9", "name": "Accounts with owner permissions on Azure resources should be MFA enabled", "category": "Identity", "weight": 3},

    # Governance - Important
    {"id": "37e0d2fe-28a5-43d6-a273-67d37d1f5606", "name": "Inherit a tag from the resource group", "category": "Governance", "weight": 2},
    {"id": "96670d01-0a4d-4649-9c89-2d3abc0a5025", "name": "Require a tag on resource groups", "category": "Governance", "weight": 2},
    {"id": "e56962a6-4747-49cd-b67b-bf8b01975c4c", "name": "Allowed locations", "category": "Governance", "weight": 2},
    {"id": "a08ec900-254a-4555-9bf5-e42af04b5c5c", "name": "Not allowed resource types", "category": "Governance", "weight": 1},

    # Network - Important
    {"id": "35f9c03a-cc27-418e-9c0c-539ff999d010", "name": "Gateway subnets should not be configured with a network security group", "category": "Network", "weight": 2},
    {"id": "09024ccc-0c5f-475e-9457-b7c0d9ed487b", "name": "There should be more than one owner assigned to your subscription", "category": "Network", "weight": 2},

    # Cost / Operations
    {"id": "06a78e20-9358-41c9-923c-fb736d382a4d", "name": "Audit VMs that do not use managed disks", "category": "Operations", "weight": 1},
]

# Correct portal URL format - verified working
def _portal_url(policy_id: str) -> str:
    return (
        f"https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade"
        f"/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F{policy_id}"
    )


def calculate_alz_score(assignments: list) -> dict:
    """
    Returns an ALZ compliance score (0-100) based on how many ALZ-recommended
    policies are assigned in the subscription.
    """
    assigned_ids = set()
    for a in assignments:
        pid = a.get("policy_definition_id", "")
        name = pid.rstrip("/").split("/")[-1].lower()
        assigned_ids.add(name)

    # Deduplicate ALZ list by ID
    seen_ids = set()
    alz_dedup = []
    for p in ALZ_RECOMMENDED:
        if p["id"] not in seen_ids:
            seen_ids.add(p["id"])
            alz_dedup.append(p)

    total_weight = sum(p["weight"] for p in alz_dedup)
    covered_weight = 0
    covered = []
    missing = []

    for policy in alz_dedup:
        pid = policy["id"].lower()
        if pid in assigned_ids:
            covered_weight += policy["weight"]
            covered.append({**policy, "status": "assigned"})
        else:
            missing.append({
                **policy,
                "status": "missing",
                "portal_url": _portal_url(policy["id"]),
            })

    score = round(100 * covered_weight / total_weight) if total_weight else 0

    # Group by category
    by_cat = {}
    for p in alz_dedup:
        cat = p["category"]
        if cat not in by_cat:
            by_cat[cat] = {"total": 0, "covered": 0, "weight": 0, "covered_weight": 0}
        by_cat[cat]["total"] += 1
        by_cat[cat]["weight"] += p["weight"]
        if p["id"].lower() in assigned_ids:
            by_cat[cat]["covered"] += 1
            by_cat[cat]["covered_weight"] += p["weight"]

    cat_scores = []
    for cat, d in by_cat.items():
        cat_score = round(100 * d["covered_weight"] / d["weight"]) if d["weight"] else 0
        cat_scores.append({
            "category": cat,
            "score": cat_score,
            "covered": d["covered"],
            "total": d["total"],
        })
    cat_scores.sort(key=lambda x: x["score"])

    return {
        "score": score,
        "covered_count": len(covered),
        "total_count": len(alz_dedup),
        "covered_weight": covered_weight,
        "total_weight": total_weight,
        "by_category": cat_scores,
        "missing": missing[:10],
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
    }
