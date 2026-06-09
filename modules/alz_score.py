"""
ALZ (Azure Landing Zone) Compliance Score.
Checks how many ALZ-recommended policies/initiatives are assigned.
"""

# ALZ recommended policies grouped by category and importance
# Source: github.com/Azure/Enterprise-Scale
ALZ_RECOMMENDED = [
    # Security - Critical
    {"id": "1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "name": "Enable Microsoft Defender for Cloud", "category": "Security", "weight": 3},
    {"id": "b954148f-4c11-4c38-8221-be76711e194a", "name": "Configure Microsoft Defender for Servers", "category": "Security", "weight": 3},
    {"id": "0961003e-5a0a-4549-abde-af6a37f2724d", "name": "Disk encryption should be enabled", "category": "Security", "weight": 3},
    {"id": "2913021d-f2fd-4f3d-b958-22354e2bdbcb", "name": "Adaptive network hardening recommendations should be applied", "category": "Security", "weight": 2},
    {"id": "9daedab3-fb2d-461e-b861-71790eead4f6", "name": "All network ports should be restricted on NSGs", "category": "Security", "weight": 2},
    {"id": "123a3936-f020-408a-ba0c-47873faf1534", "name": "Require encryption on Data Lake Store accounts", "category": "Security", "weight": 2},

    # Monitoring - Critical
    {"id": "4da35fc9-c9e7-4960-aec9-797fe7d9051d", "name": "Enable Azure Monitor for VMs", "category": "Monitoring", "weight": 3},
    {"id": "8e3e61b3-0b32-22d5-4edf-55f87fdb5955", "name": "Deploy Log Analytics agent for Linux VMs", "category": "Monitoring", "weight": 2},
    {"id": "ae8a10e6-19d6-44a3-a02d-a2bdfc707742", "name": "Deploy Log Analytics agent for Windows VMs", "category": "Monitoring", "weight": 2},

    # Governance - Important
    {"id": "37e0d2fe-28a5-43d6-a273-67d37d1f5606", "name": "Inherit a tag from the resource group", "category": "Governance", "weight": 2},
    {"id": "96670d01-0a4d-4649-9c89-2d3abc0a5025", "name": "Require a tag on resource groups", "category": "Governance", "weight": 2},
    {"id": "e56962a6-4747-49cd-b67b-bf8b01975c4c", "name": "Allowed locations", "category": "Governance", "weight": 2},
    {"id": "a08ec900-254a-4555-9bf5-e42af04b5c5c", "name": "Not allowed resource types", "category": "Governance", "weight": 1},

    # Identity - Important
    {"id": "9297c21d-2ed6-4474-b48f-163f75654ce3", "name": "MFA should be enabled on accounts with owner permissions", "category": "Identity", "weight": 3},
    {"id": "aa633080-8b72-40c4-a2d7-d00c03e80bed", "name": "MFA should be enabled on accounts with write permissions", "category": "Identity", "weight": 3},
    {"id": "e3576e28-8b17-4677-84c3-db2990658d64", "name": "MFA should be enabled on accounts with read permissions", "category": "Identity", "weight": 2},

    # Network - Important
    {"id": "e372f825-a257-4fb8-9175-797a8a8627d4", "name": "Subnets should have a Network Security Group", "category": "Network", "weight": 2},
    {"id": "b0f33259-77d7-4c9e-aac6-3aabcfae693c", "name": "Management ports of VMs should be protected with JIT", "category": "Network", "weight": 2},

    # Cost / Operations
    {"id": "06a78e20-9358-41c9-923c-fb736d382a4d", "name": "Audit VMs that do not use managed disks", "category": "Operations", "weight": 1},
]

# ALZ recommended initiatives (policy sets)
ALZ_INITIATIVES = [
    {"id": "1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "name": "Microsoft Cloud Security Benchmark", "category": "Security", "weight": 5},
    {"id": "179d1daa-458f-4e47-8086-2a68d0d6c38f", "name": "NIST SP 800-53 Rev. 5", "category": "Compliance", "weight": 3},
    {"id": "496eeda9-8f2f-4d5e-8dfd-204f6c3eb046", "name": "CIS Microsoft Azure Foundations Benchmark", "category": "Compliance", "weight": 3},
]


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

    total_weight = sum(p["weight"] for p in ALZ_RECOMMENDED)
    covered_weight = 0
    covered = []
    missing = []

    for policy in ALZ_RECOMMENDED:
        pid = policy["id"].lower()
        if pid in assigned_ids:
            covered_weight += policy["weight"]
            covered.append({**policy, "status": "assigned"})
        else:
            missing.append({**policy, "status": "missing",
                            "portal_url": f"https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F{policy['id']}"})

    score = round(100 * covered_weight / total_weight) if total_weight else 0

    # Group by category
    by_cat = {}
    for p in ALZ_RECOMMENDED:
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
        "total_count": len(ALZ_RECOMMENDED),
        "covered_weight": covered_weight,
        "total_weight": total_weight,
        "by_category": cat_scores,
        "missing": missing[:10],  # top 10 missing
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
    }
