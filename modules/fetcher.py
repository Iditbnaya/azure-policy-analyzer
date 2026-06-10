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
                except Exception as _tid_err:
                    print(f"  [warn] could not get tenant_id: {_tid_err}")

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
        Returns compliance data matching Azure Portal dashboard numbers.
        - Policy Compliance: counts individual policy definitions (not assignments)
        - Initiative Compliance: counts policy set assignment results
        - Resource Compliance: total compliant vs non-compliant resources
        - Pending Remediation: assignments with DeployIfNotExists/Modify effects
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

            # Policy definition level counts (matches portal "Policy Compliance")
            pol_def_compliant = 0
            pol_def_non_compliant = 0
            pol_def_error = 0
            pol_def_other = 0

            # Initiative level counts (matches portal "Initiative Compliance")
            ini_compliant = 0
            ini_non_compliant = 0

            # Resource counts (matches portal "Overall Resource Compliance")
            res_compliant = 0
            res_non_compliant = 0

            # Pending remediation
            pending_remediation = 0

            for summary in result.value or []:
                # Top-level resource summary
                top_res = summary.results
                if top_res:
                    res_non_compliant_top = int(getattr(top_res, "non_compliant_resources", 0) or 0)
                    res_non_compliant = max(res_non_compliant, res_non_compliant_top)

                for pa in summary.policy_assignments or []:
                    r = pa.results
                    nc_pol = int(getattr(r, "non_compliant_policies", 0) or 0)
                    nc_res = int(getattr(r, "non_compliant_resources", 0) or 0)
                    pa_id = pa.policy_assignment_id or ""

                    # Per-definition counts from policy_definitions list
                    pol_defs = getattr(pa, "policy_definitions", None) or []
                    if pol_defs:
                        for pd in pol_defs:
                            pd_r = pd.results
                            pd_nc = int(getattr(pd_r, "non_compliant_resources", 0) or 0)
                            pd_effect = (getattr(pd, "effect", "") or "").lower()
                            if pd_nc > 0:
                                if "error" in (getattr(pd, "compliance_state", "") or "").lower():
                                    pol_def_error += 1
                                else:
                                    pol_def_non_compliant += 1
                            else:
                                pol_def_compliant += 1
                    else:
                        # Fallback: count at assignment level
                        if nc_pol > 0:
                            pol_def_non_compliant += nc_pol
                        else:
                            pol_def_compliant += 1

                    # Pending remediation: assignments with non-compliant resources
                    if nc_res > 0:
                        pending_remediation += 1

                    # Initiative detection: policySetDefinitions in the ID
                    if "policysetdefinitions" in pa_id.lower():
                        if nc_res > 0:
                            ini_non_compliant += 1
                        else:
                            ini_compliant += 1

            # Resource compliance: try to get from top-level
            total_policies = pol_def_compliant + pol_def_non_compliant + pol_def_error + pol_def_other

            # For resource %, we only have non-compliant from the API
            # Use non_compliant count with a note that total isn't available via this endpoint
            return {
                "policy_compliant": pol_def_compliant,
                "policy_non_compliant": pol_def_non_compliant,
                "policy_error": pol_def_error,
                "policy_other": pol_def_other,
                "policy_total": total_policies,
                "initiative_compliant": ini_compliant,
                "initiative_non_compliant": ini_non_compliant,
                "initiative_total": ini_compliant + ini_non_compliant,
                "resource_non_compliant": res_non_compliant,
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
                # Safely serialize parameters - ParameterValuesValue objects need special handling
                params = {}
                if a.parameters:
                    for k, v in a.parameters.items():
                        try:
                            val = v.value if hasattr(v, "value") else v
                            params[k] = {"value": val}
                        except Exception:
                            params[k] = {"value": str(v)}

                # Extract current effect from parameters
                effect = ""
                for k, v in params.items():
                    if "effect" in k.lower():
                        effect = str(v.get("value", "")).lower()

                meta = _safe_dict(a.metadata) if a.metadata else {}
                created_on = None
                if meta.get("createdOn"):
                    created_on = str(meta["createdOn"])

                assignments.append({
                    "id": a.id or "",
                    "name": a.name or "",
                    "policy_definition_id": a.policy_definition_id or "",
                    "scope": a.scope or "",
                    "display_name": a.display_name or a.name or "",
                    "parameters": params,
                    "effect_param": effect,
                    "enforcement_mode": str(a.enforcement_mode) if a.enforcement_mode else "Default",
                    "created_on": created_on,
                })
            return assignments
        except Exception as e:
            print(f"  [warn] assignments {subscription_id}: {e}")
            return []

    def get_non_compliant_resources(self, subscription_id: str, assignment_id: str, top: int = 20) -> list:
        """Get individual non-compliant resources for a specific assignment."""
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient
            client = PolicyInsightsClient(
                credential=self.credential,
                subscription_id=subscription_id,
            )
            from azure.mgmt.policyinsights.models import QueryOptions
            query_opts = QueryOptions(
                filter=f"PolicyAssignmentId eq '{assignment_id}' and ComplianceState eq 'NonCompliant'",
                top=top,
            )
            result = client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=subscription_id,
                query_options=query_opts,
            )
            resources = []
            for r in (result or []):
                resources.append({
                    "resource_id": r.resource_id or "",
                    "resource_type": r.resource_type or "",
                    "resource_group": r.resource_group or "",
                    "resource_location": r.resource_location or "",
                    "compliance_state": r.compliance_state or "",
                    "timestamp": str(r.timestamp) if r.timestamp else "",
                })
            return resources
        except Exception as e:
            print(f"  [warn] non-compliant resources: {e}")
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
                    "deprecated": bool(meta.get("deprecated", False)) if meta else False,
                    # Semantic fingerprint - same extractor as custom policies
                    "operation": op["operation"],
                    "resource_types": list(op["resource_types"]),
                })
            return policies
        except Exception as e:
            print(f"  [warn] built-in policies: {e}")
            return []
