import json
import re

VALID_EFFECTS = {
    "Audit", "AuditIfNotExists", "Deny", "DeployIfNotExists",
    "Disabled", "Modify", "Append", "DenyAction", "Manual",
}


class PolicyAnalyzer:
    """Analyzes custom Azure policy definitions for health issues."""

    def analyze(self, custom_policies: list, assignments: list, compliance_data: list) -> dict:
        # Build set of assigned policy definition IDs
        assigned_ids = set()
        for a in assignments:
            pid = (a.get("policy_definition_id") or "").lower()
            if pid:
                assigned_ids.add(pid)

        analyzed = []
        for policy in custom_policies:
            issues, warnings = [], []

            # 1. Not assigned anywhere
            pid = (policy.get("id") or "").lower()
            if pid and pid not in assigned_ids:
                issues.append({
                    "type": "NOT_ASSIGNED",
                    "severity": "warning",
                    "message": "Policy is defined but not assigned to any scope",
                    "fix": "Assign this policy to a management group, subscription, or resource group - or delete it if obsolete",
                })

            # 2. Missing description
            if not policy.get("description", "").strip():
                warnings.append({
                    "type": "MISSING_DESCRIPTION",
                    "severity": "info",
                    "message": "Policy has no description",
                    "fix": "Add a clear description explaining the policy purpose and compliance intent",
                })

            # 3. Missing category
            if not policy.get("category", "").strip():
                warnings.append({
                    "type": "MISSING_CATEGORY",
                    "severity": "info",
                    "message": "Policy metadata is missing a category",
                    "fix": 'Add a category in metadata (e.g., "Security", "Compute", "Storage", "Network")',
                })

            # 4. Effect validity
            effect = policy.get("effect", "")
            if effect and effect not in ("Parameterized", "Unknown", ""):
                if effect not in VALID_EFFECTS and effect.title() not in VALID_EFFECTS:
                    issues.append({
                        "type": "INVALID_EFFECT",
                        "severity": "error",
                        "message": f'Invalid effect: "{effect}"',
                        "fix": f"Use one of: {', '.join(sorted(VALID_EFFECTS))}",
                    })
                elif effect not in VALID_EFFECTS and effect.title() in VALID_EFFECTS:
                    warnings.append({
                        "type": "EFFECT_CASE",
                        "severity": "warning",
                        "message": f'Effect "{effect}" should be PascalCase: "{effect.title()}"',
                        "fix": f'Change effect from "{effect}" to "{effect.title()}"',
                    })

            # 5. Old API versions in rule
            issues.extend(self._check_api_versions(policy.get("policy_rule")))

            # 6. Policy rule structure
            issues.extend(self._check_rule_structure(policy.get("policy_rule")))

            # 7. Generic/poor display name
            display_name = policy.get("display_name", "").strip()
            name = policy.get("name", "").strip()
            if display_name and (display_name == name or len(display_name) < 5):
                warnings.append({
                    "type": "POOR_NAMING",
                    "severity": "info",
                    "message": "Display name appears auto-generated or too short",
                    "fix": "Set a meaningful display name that clearly describes the policy intent",
                })

            # Determine overall severity
            if any(i["severity"] == "error" for i in issues):
                severity = "error"
            elif any(i["severity"] == "warning" for i in issues + warnings):
                severity = "warning"
            elif warnings:
                severity = "info"
            else:
                severity = "ok"

            analyzed.append({
                **policy,
                "issues": issues,
                "warnings": warnings,
                "severity": severity,
                "issue_count": len(issues),
                "warning_count": len(warnings),
            })

        # Sort: errors first
        order = {"error": 0, "warning": 1, "info": 2, "ok": 3}
        analyzed.sort(key=lambda p: order.get(p["severity"], 3))

        problematic = [p for p in analyzed if p["severity"] in ("error", "warning")]

        return {
            "all": analyzed,
            "problematic": problematic,
            "stats": {
                "total": len(analyzed),
                "errors": sum(1 for p in analyzed if p["severity"] == "error"),
                "warnings": sum(1 for p in analyzed if p["severity"] == "warning"),
                "info": sum(1 for p in analyzed if p["severity"] == "info"),
                "ok": sum(1 for p in analyzed if p["severity"] == "ok"),
            },
        }

    def _check_api_versions(self, policy_rule) -> list:
        issues = []
        if not policy_rule:
            return issues
        rule_str = json.dumps(policy_rule) if isinstance(policy_rule, dict) else str(policy_rule)
        old = list(set(re.findall(r'201[0-8]-\d{2}-\d{2}', rule_str)))
        if old:
            issues.append({
                "type": "OLD_API_VERSION",
                "severity": "warning",
                "message": f"Policy references old API version(s): {', '.join(old)}",
                "fix": "Update aliases to use current API versions. Check https://docs.microsoft.com/en-us/azure/governance/policy/reference/alias-changes",
            })
        return issues

    def _check_rule_structure(self, policy_rule) -> list:
        issues = []
        if not policy_rule:
            issues.append({
                "type": "EMPTY_RULE",
                "severity": "error",
                "message": "Policy rule is empty or missing",
                "fix": 'Add a valid policy rule with "if" (condition) and "then" (effect) blocks',
            })
            return issues
        rule = policy_rule if isinstance(policy_rule, dict) else {}
        if "if" not in rule:
            issues.append({
                "type": "MISSING_IF",
                "severity": "error",
                "message": 'Policy rule is missing the "if" condition block',
                "fix": 'Add an "if" block that specifies when this policy applies',
            })
        if "then" not in rule:
            issues.append({
                "type": "MISSING_THEN",
                "severity": "error",
                "message": 'Policy rule is missing the "then" action block',
                "fix": 'Add a "then" block with an "effect" field',
            })
        return issues
