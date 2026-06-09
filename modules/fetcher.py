import json


def _safe_dict(obj):
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
        if effect.startswith("[") and "parameters" in effect:
            return "Parameterized"
        return effect or "Unknown"
    return "Unknown"


class PolicyFetcher:
    """Fetches policy definitions, assignments, compliance, and MG hierarchy."""

    def __init__(self, credential):
        self.credential = credential

    # ------------------------------------------------------------------
    # Management Group hierarchy
    # ------------------------------------------------------------------

    def get_management_group_tree(self, tenant_id: str = None):
        """
        Return the full MG hierarchy as a nested dict, or None on failure.
        Requires azure-mgmt-managementgroups and MG read permissions.
        """
        try:
            from azure.mgmt.managementgroups import ManagementGroupsAPI
            from azure.mgmt.subscription import SubscriptionClient

            if not tenant_id:
                try:
                    sc = SubscriptionClient(self.credential)
                    tenants = list(sc.tenants.list())
                    if tenants:
                        tenant_id = tenants[0].tenant_id
                except Exception:
                    pass

            if not tenant_id:
                return None

            client = ManagementGroupsAPI(self.credential)
            root = client.management_groups.get(
                group_id=tenant_id,
                expand="children",
                recurse=True,
            )
            return self._mg_to_dict(root)
        except Exception as e:
            print(f"  [warn] MG tree failed: {e}")
            return None

    def _mg_to_dict(self, node) -> dict:
        name = getattr(node, "display_name", None) or getattr(node, "name", "") or ""
        children = []
        for child in getattr(node, "children", None) or []:
            ct = child.type
            if hasattr(ct, "value"):
                ct = ct.value
            if "/subscriptions" in str(ct).lower():
                children.append({
                    "type": "subscription",
                    "id": child.name or "",
                    "name": child.display_name or child.name or "",
                })
            else:
                children.append(self._mg_to_dict(child))
        return {
            "type": "managementGroup",
            "id": getattr(node, "id", "") or "",
            "name": name,
            "children": children,
        }

    # ------------------------------------------------------------------
    # Compliance, custom policies, assignments, built-ins
    # ------------------------------------------------------------------

    def get_compliance_summary(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient
            client = PolicyInsightsClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            result = client.policy_states.summarize_for_subscription(
                policy_states_summary_resource="latest",
                subscription_id=subscription_id,
            )
            items = []
            for summary in result.value or []:
                for pa in summary.policy_assignments or []:
                    r = pa.results
                    nc = getattr(r, "non_compliant_resources", 0) or 0
                    if nc > 0:
                        pa_id = pa.policy_assignment_id or ""
                        items.append({
                            "policy_assignment_id": pa_id,
                            "policy_assignment_name": pa_id.split("/")[-1] if pa_id else "Unknown",
                            "non_compliant_resources": nc,
                            "non_compliant_policies": getattr(r, "non_compliant_policies", 0) or 0,
                        })
            items.sort(key=lambda x: x["non_compliant_resources"], reverse=True)
            return items
        except Exception as e:
            print(f"  [warn] compliance {subscription_id}: {e}")
            return []

    def get_compliance_overview(self, subscription_id: str) -> dict:
        """
        Returns richer compliance data for the dashboard:
        policy compliance counts, resource compliance %, pending remediation.
        """
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient
            client = PolicyInsightsClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            result = client.policy_states.summarize_for_subscription(
                policy_states_summary_resource="latest",
                subscription_id=subscription_id,
            )
            policy_compliant = 0
            policy_non_compliant = 0
            policy_error = 0
            resource_compliant = 0
            resource_non_compliant = 0
            pending_remediation = 0

            for summary in result.value or []:
                # Top-level resource summary
                res = summary.results
                if res:
                    resource_compliant += getattr(res, "query_results_uri", 0) or 0

                for pa in summary.policy_assignments or []:
                    r = pa.results
                    nc_pol = getattr(r, "non_compliant_policies", 0) or 0
                    nc_res = getattr(r, "non_compliant_resources", 0) or 0
                    # Each assignment with no non-compliant = compliant
                    if nc_pol == 0 and nc_res == 0:
                        policy_compliant += 1
                    else:
                        policy_non_compliant += 1
                    resource_non_compliant += nc_res

                    # Pending remediation = DINE/Modify assignments with non-compliant resources
                    pa_id = pa.policy_assignment_id or ""
                    if nc_res > 0:
                        pending_remediation += 1

            total_policies = policy_compliant + policy_non_compliant + policy_error
            total_resources = resource_compliant + resource_non_compliant

            return {
                "policy_compliant": policy_compliant,
                "policy_non_compliant": policy_non_compliant,
                "policy_error": policy_error,
                "policy_total": total_policies,
                "resource_compliant": resource_compliant,
                "resource_non_compliant": resource_non_compliant,
                "resource_total": total_resources,
                "resource_compliance_pct": round(100 * resource_compliant / total_resources, 1) if total_resources else 0,
                "pending_remediation": pending_remediation,
            }
        except Exception as e:
            print(f"  [warn] compliance overview {subscription_id}: {e}")
            return {}

    def get_custom_policies(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            from modules.recommender import _extract_operation
            client = PolicyClient(credential=self.credential, subscription_id=subscription_id)
            policies = []
            for p in client.policy_definitions.list():
                pt = p.policy_type
                if hasattr(pt, "value"):
                    pt = pt.value
                if str(pt) != "Custom":
                    continue
                meta = _safe_dict(p.metadata)
                rule = _safe_dict(p.policy_rule)
                op = _extract_operation(rule)
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
                    "deprecated": bool(meta.get("deprecated", False)) if meta else False,
                    "operation": op["operation"],
                    "resource_types": list(op["resource_types"]),
                })
            return policies
        except Exception as e:
            print(f"  [warn] custom policies {subscription_id}: {e}")
            return []

    def get_policy_assignments(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            client = PolicyClient(credential=self.credential, subscription_id=subscription_id)
            assignments = []
            for a in client.policy_assignments.list():
                assignments.append({
                    "id": a.id or "",
                    "name": a.name or "",
                    "policy_definition_id": a.policy_definition_id or "",
                    "scope": a.scope or "",
                    "display_name": a.display_name or a.name or "",
                    "parameters": _safe_dict(a.parameters) if a.parameters else {},
                })
            return assignments
        except Exception as e:
            print(f"  [warn] assignments {subscription_id}: {e}")
            return []

    def get_builtin_initiatives(self, subscription_id: str) -> list:
        """Fetch built-in policy set definitions (initiatives)."""
        try:
            from azure.mgmt.resource import PolicyClient
            client = PolicyClient(credential=self.credential, subscription_id=subscription_id)
            initiatives = []
            for p in client.policy_set_definitions.list_built_in():
                meta = _safe_dict(p.metadata)
                policy_defs = []
                for pd in (p.policy_definitions or []):
                    pid = pd.policy_definition_id or ""
                    policy_defs.append(pid.split("/")[-1])
                initiatives.append({
                    "id": p.id or "",
                    "name": p.name or "",
                    "display_name": p.display_name or p.name or "",
                    "description": p.description or "",
                    "category": meta.get("category", "") if meta else "",
                    "policy_definition_names": policy_defs,
                    "policy_count": len(policy_defs),
                })
            return initiatives
        except Exception as e:
            print(f"  [warn] initiatives: {e}")
            return []


    def get_builtin_policies(self, subscription_id: str) -> list:
        try:
            from azure.mgmt.resource import PolicyClient
            from modules.recommender import _extract_operation
            client = PolicyClient(credential=self.credential, subscription_id=subscription_id)
            policies = []
            for p in client.policy_definitions.list_built_in():
                meta = _safe_dict(p.metadata)
                rule = _safe_dict(p.policy_rule)
                op = _extract_operation(rule)
                policies.append({
                    "id": p.id or "",
                    "name": p.name or "",
                    "display_name": p.display_name or p.name or "",
                    "description": p.description or "",
                    "category": meta.get("category", "") if meta else "",
                    "effect": _extract_effect(rule),
                    # Semantic fingerprint - same extractor as custom policies
                    "operation": op["operation"],
                    "resource_types": list(op["resource_types"]),
                })
            return policies
        except Exception as e:
            print(f"  [warn] built-in policies: {e}")
            return []
