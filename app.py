import sys
import os
import uuid
import json
import queue as queue_module
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.auth import AuthManager
from modules.fetcher import PolicyFetcher
from modules.analyzer import PolicyAnalyzer
from modules.recommender import PolicyRecommender
import modules.policy_cache as policy_cache

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

auth_manager = AuthManager()
pending_scans = {}       # scan_id -> params
scan_contexts = {}       # scan_id (reused as session key) -> compact scan summary for agent

_LAST_SCAN_CONTEXT = {}  # simple in-process "last scan" for agent context


def _scan_subscription(sub_id, sub_name, credential, builtin_policies):
    fetcher = PolicyFetcher(credential)
    analyzer = PolicyAnalyzer()
    recommender = PolicyRecommender()

    with ThreadPoolExecutor(max_workers=4) as ex:
        f_comp = ex.submit(fetcher.get_compliance_summary, sub_id)
        f_overview = ex.submit(fetcher.get_compliance_overview, sub_id)
        f_custom = ex.submit(fetcher.get_custom_policies, sub_id)
        f_assign = ex.submit(fetcher.get_policy_assignments, sub_id)
        compliance = f_comp.result()
        overview = f_overview.result()
        custom_policies = f_custom.result()
        assignments = f_assign.result()

    analyzed = analyzer.analyze(custom_policies, assignments, compliance)
    recs = recommender.get_recommendations(analyzed["problematic"], builtin_policies)

    # Recommended assignments: top built-in policies NOT already assigned
    assigned_def_names = {
        a.get("policy_definition_id", "").rstrip("/").split("/")[-1].lower()
        for a in assignments
    }
    POPULAR_RECOMMENDED = [
        {"name": "37e0d2fe-28a5-43d6-a273-67d37d1f5606", "display_name": "Inherit a tag from the resource group", "description": "Automated inheritance of tags from Resource Group to resources.", "category": "Tags"},
        {"name": "96670d01-0a4d-4649-9c89-2d3abc0a5025", "display_name": "Require a tag on resource groups", "description": "Enforce existence of a tag on Resource Group.", "category": "Tags"},
        {"name": "a08ec900-254a-4555-9bf5-e42af04b5c5c", "display_name": "Not allowed resource types", "description": "Block the creation of specified resource types.", "category": "General"},
        {"name": "72650e9f-97bc-4b2a-0b59-daab3dc5ee70", "display_name": "Windows Defender Exploit Guard should be enabled", "description": "Deploy security baselines for Windows VMs.", "category": "Security"},
        {"name": "4da35fc9-c9e7-4960-aec9-797fe7d9051d", "display_name": "Enable Azure Monitor for VMs", "description": "Install monitoring and dependency agents on VMs.", "category": "Monitoring"},
        {"name": "1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "display_name": "Enable Microsoft Defender for Cloud", "description": "Monitor security recommendations by Microsoft Defender for Cloud.", "category": "Security Center"},
        {"name": "e56962a6-4747-49cd-b67b-bf8b01975c4c", "display_name": "Allowed locations", "description": "Restrict the locations your organization can create resources.", "category": "General"},
        {"name": "06a78e20-9358-41c9-923c-fb736d382a4d", "display_name": "Audit VMs that do not use managed disks", "description": "Audit VMs not using managed disks.", "category": "Compute"},
        {"name": "0961003e-5a0a-4549-abde-af6a37f2724d", "display_name": "Virtual machines should encrypt temp disks, caches, and data flows", "description": "Enforce disk encryption to protect data at rest.", "category": "Security"},
    ]
    recommended_assignments = [
        {**r, "portal_url": f"https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F{r['name']}"}
        for r in POPULAR_RECOMMENDED
        if r["name"].lower() not in assigned_def_names
    ][:6]

    # Insights analysis
    from modules.insights import (
        find_duplicate_policies,
        find_deprecated_assignments,
        find_initiative_opportunities,
        find_audit_ready_for_deny,
    )
    from modules.alz_score import calculate_alz_score

    insights = {
        "duplicates": find_duplicate_policies(custom_policies, assignments),
        "deprecated": find_deprecated_assignments(custom_policies, builtin_policies, assignments),
        "initiatives": find_initiative_opportunities(custom_policies, assignments, builtin_policies),
        "audit_ready": find_audit_ready_for_deny(assignments),
    }

    alz_score = calculate_alz_score(assignments)

    return {
        "subscription_id": sub_id,
        "subscription_name": sub_name,
        "compliance": compliance,
        "compliance_overview": overview,
        "recommended_assignments": recommended_assignments,
        "custom_policies": {
            "stats": analyzed["stats"],
            "all": analyzed["all"],
            "problematic": analyzed["problematic"],
        },
        "recommendations": recs,
        "assignments": assignments,
        "insights": insights,
        "alz_score": alz_score,
    }


def _build_scan_context(results: list) -> str:
    """Build a compact text summary of scan results for the agent."""
    lines = []
    for r in results:
        lines.append(f"Subscription: {r['subscription_name']} ({r['subscription_id']})")
        stats = r["custom_policies"].get("stats", {})
        lines.append(
            f"  Custom policies: {stats.get('total',0)} total, "
            f"{stats.get('errors',0)} errors, {stats.get('warnings',0)} warnings"
        )
        for p in r["custom_policies"].get("problematic", []):
            issues = [i["message"] for i in (p.get("issues") or []) + (p.get("warnings") or [])]
            lines.append(
                f"  [POLICY ISSUE] {p['display_name']} ({p['name']}) - "
                f"severity={p['severity']} - issues: {'; '.join(issues[:3])}"
            )
        for c in r["compliance"][:5]:
            lines.append(
                f"  [COMPLIANCE] Assignment '{c['policy_assignment_name']}' "
                f"- {c['non_compliant_resources']} non-compliant resources"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Routes - connect & MG tree
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Popular recommended assignments (module-level so workers can access it)
# ---------------------------------------------------------------------------
POPULAR_RECOMMENDED = [
    {"name": "37e0d2fe-28a5-43d6-a273-67d37d1f5606", "display_name": "Inherit a tag from the resource group", "description": "Automated inheritance of tags from Resource Group to resources.", "category": "Tags"},
    {"name": "96670d01-0a4d-4649-9c89-2d3abc0a5025", "display_name": "Require a tag on resource groups", "description": "Enforce existence of a tag on Resource Group.", "category": "Tags"},
    {"name": "a08ec900-254a-4555-9bf5-e42af04b5c5c", "display_name": "Not allowed resource types", "description": "Block the creation of specified resource types.", "category": "General"},
    {"name": "72650e9f-97bc-4b2a-0b59-daab3dc5ee70", "display_name": "Windows Defender Exploit Guard should be enabled", "description": "Deploy security baselines for Windows VMs.", "category": "Security"},
    {"name": "4da35fc9-c9e7-4960-aec9-797fe7d9051d", "display_name": "Enable Azure Monitor for VMs", "description": "Install monitoring and dependency agents on VMs.", "category": "Monitoring"},
    {"name": "1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "display_name": "Enable Microsoft Defender for Cloud", "description": "Monitor security recommendations by Microsoft Defender for Cloud.", "category": "Security Center"},
    {"name": "e56962a6-4747-49cd-b67b-bf8b01975c4c", "display_name": "Allowed locations", "description": "Restrict the locations your organization can create resources.", "category": "General"},
    {"name": "06a78e20-9358-41c9-923c-fb736d382a4d", "display_name": "Audit VMs that do not use managed disks", "description": "Audit VMs not using managed disks.", "category": "Compute"},
    {"name": "0961003e-5a0a-4549-abde-af6a37f2724d", "display_name": "Virtual machines should encrypt temp disks, caches, and data flows", "description": "Enforce disk encryption to protect data at rest.", "category": "Security"},
]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/connect", methods=["POST"])
def connect():
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
        # Pre-warm token on the main thread so parallel scan workers reuse it from cache
        credential.get_token("https://management.azure.com/.default")
        subs = auth_manager.list_subscriptions(credential)
        return jsonify({"status": "ok", "subscriptions": subs})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/mg-tree")
def mg_tree_endpoint():
    tenant_id = request.args.get("tenant_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
        fetcher = PolicyFetcher(credential)
        tree = fetcher.get_management_group_tree(tenant_id)
        return jsonify({"status": "ok", "tree": tree})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# ---------------------------------------------------------------------------
# Cache routes
# ---------------------------------------------------------------------------

@app.route("/api/cache/status")
def cache_status():
    meta = policy_cache.get_meta()
    age_h = policy_cache.cache_age_hours()
    count = len(policy_cache.load_local())
    return jsonify({
        "count": count,
        "age_hours": round(age_h, 1) if age_h != float("inf") else None,
        "updated_iso": meta.get("updated_iso"),
        "source": meta.get("source", "none"),
        "fresh": age_h < 24,
    })


@app.route("/api/cache/refresh", methods=["POST"])
def cache_refresh():
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    sub_id = data.get("subscription_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
        policies, source = policy_cache.get(credential, sub_id, force=True)
        return jsonify({"status": "ok", "count": len(policies), "source": source})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# ---------------------------------------------------------------------------
# Scan routes (SSE streaming)
# ---------------------------------------------------------------------------

@app.route("/api/scan/init", methods=["POST"])
def scan_init():
    scan_id = str(uuid.uuid4())
    pending_scans[scan_id] = request.json or {}
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/stream/<scan_id>")
def scan_stream_route(scan_id):
    params = pending_scans.pop(scan_id, None)
    if not params:
        return jsonify({"error": "Invalid or expired scan ID"}), 404

    tenant_id = params.get("tenant_id", "").strip()
    sub_ids = params.get("subscription_ids", [])
    sub_names = params.get("subscription_names", {})

    if not sub_ids:
        return jsonify({"error": "No subscriptions selected"}), 400

    credential = auth_manager.get_credential(tenant_id)

    def generate():
        def evt(data):
            return f"data: {json.dumps(data)}\n\n"

        def log(msg):
            return evt({"type": "log", "msg": msg})

        yield evt({"type": "start", "total": len(sub_ids)})
        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Scan started - {len(sub_ids)} subscription(s) selected")

        # Pre-warm credential token
        yield evt({"type": "progress", "msg": "Authenticating..."})
        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Authenticating to Azure...")
        try:
            credential.get_token("https://management.azure.com/.default")
            yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Authentication successful")
        except Exception as e:
            yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] [WARN] Token pre-warm: {e}")

        # Load built-in policies from cache
        yield evt({"type": "progress", "msg": "Loading built-in policies from cache..."})
        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Loading built-in policy cache...")
        builtins, cache_source = policy_cache.get(credential, sub_ids[0])
        yield evt({"type": "builtins", "count": len(builtins), "cache_source": cache_source})
        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Loaded {len(builtins)} built-in policies (source: {cache_source})")
        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Starting parallel scan ({min(5, len(sub_ids))} workers)...")

        # Scan subscriptions in parallel, stream results
        result_q = queue_module.Queue()
        log_q = queue_module.Queue()
        accumulated = []

        def worker(sid):
            sname = sub_names.get(sid, sid)
            ts = lambda: __import__('datetime').datetime.now().strftime('%H:%M:%S')
            log_q.put(f"[{ts()}] [{sname}] Fetching compliance state...")
            try:
                fetcher = PolicyFetcher(credential)
                analyzer = PolicyAnalyzer()
                recommender = PolicyRecommender()

                # Per-call timeout: if any Azure API call hangs, fail after 90s
                CALL_TIMEOUT = 90

                with ThreadPoolExecutor(max_workers=4) as ex:
                    f_comp   = ex.submit(fetcher.get_compliance_summary, sid)
                    f_ov     = ex.submit(fetcher.get_compliance_overview, sid)
                    f_custom = ex.submit(fetcher.get_custom_policies, sid)
                    f_assign = ex.submit(fetcher.get_policy_assignments, sid)
                    try:
                        compliance       = f_comp.result(timeout=CALL_TIMEOUT)
                    except Exception as e:
                        log_q.put(f"[{ts()}] [{sname}] [WARN] compliance timed out/failed: {e}")
                        compliance = []
                    try:
                        overview         = f_ov.result(timeout=CALL_TIMEOUT)
                    except Exception as e:
                        log_q.put(f"[{ts()}] [{sname}] [WARN] overview timed out/failed: {e}")
                        overview = {}
                    try:
                        custom_policies  = f_custom.result(timeout=CALL_TIMEOUT)
                    except Exception as e:
                        log_q.put(f"[{ts()}] [{sname}] [WARN] custom policies timed out/failed: {e}")
                        custom_policies = []
                    try:
                        assignments      = f_assign.result(timeout=CALL_TIMEOUT)
                    except Exception as e:
                        log_q.put(f"[{ts()}] [{sname}] [WARN] assignments timed out/failed: {e}")
                        assignments = []

                log_q.put(f"[{ts()}] [{sname}] Found {len(compliance)} non-compliant assignments, {len(custom_policies)} custom policies, {len(assignments)} assignments")

                analyzed = analyzer.analyze(custom_policies, assignments, compliance)
                stats = analyzed["stats"]
                log_q.put(f"[{ts()}] [{sname}] Analysis: {stats.get('errors',0)} errors, {stats.get('warnings',0)} warnings, {stats.get('ok',0)} healthy")

                recs = recommender.get_recommendations(analyzed["problematic"], builtins)
                log_q.put(f"[{ts()}] [{sname}] Generated {len(recs)} built-in replacement recommendations")

                from modules.alz_score import calculate_alz_score
                alz = calculate_alz_score(assignments)
                log_q.put(f"[{ts()}] [{sname}] ALZ compliance score: {alz['score']}% (grade {alz['grade']})")

                from modules.insights import find_duplicate_policies, find_deprecated_assignments, find_initiative_opportunities, find_audit_ready_for_deny
                insights = {
                    "duplicates": find_duplicate_policies(custom_policies, assignments),
                    "deprecated": find_deprecated_assignments(custom_policies, builtins, assignments),
                    "initiatives": find_initiative_opportunities(custom_policies, assignments, builtins),
                    "audit_ready": find_audit_ready_for_deny(assignments),
                }
                if insights["duplicates"]:
                    log_q.put(f"[{ts()}] [{sname}] ♻️  {len(insights['duplicates'])} duplicate policy groups detected")
                if insights["deprecated"]:
                    log_q.put(f"[{ts()}] [{sname}] 🚫 {len(insights['deprecated'])} deprecated/broken assignments")
                if insights["audit_ready"]:
                    ready = sum(1 for a in insights["audit_ready"] if a["tier"] == "ready")
                    log_q.put(f"[{ts()}] [{sname}] 🎓 {len(insights['audit_ready'])} audit assignments ({ready} ready for Deny)")

                assigned_def_names = {a.get("policy_definition_id","").rstrip("/").split("/")[-1].lower() for a in assignments}
                # Reference POPULAR_RECOMMENDED directly from module scope (no import needed - same file)
                _popular = POPULAR_RECOMMENDED
                recommended_assignments = [
                    {**r, "portal_url": f"https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F{r['name']}"}
                    for r in _popular if r["name"].lower() not in assigned_def_names
                ][:6]

                result_q.put(("result", {
                    "subscription_id": sid,
                    "subscription_name": sname,
                    "compliance": compliance,
                    "compliance_overview": overview,
                    "recommended_assignments": recommended_assignments,
                    "custom_policies": {
                        "stats": analyzed["stats"],
                        "all": analyzed["all"],
                        "problematic": analyzed["problematic"],
                    },
                    "recommendations": recs,
                    "assignments": assignments,
                    "insights": insights,
                    "alz_score": alz,
                }))
                log_q.put(f"[{ts()}] [{sname}] ✅ Scan complete")
            except Exception as e:
                import traceback; traceback.print_exc()
                log_q.put(f"[{ts()}] [{sname}] ❌ Error: {e}")
                result_q.put(("error", {"subscription_id": sid, "subscription_name": sname, "error": str(e)}))

        n_workers = min(5, len(sub_ids))
        MAX_TOTAL_WAIT = 600  # 10 minutes total scan timeout
        import time as _time
        scan_start = _time.time()
        ping_count = 0

        with ThreadPoolExecutor(max_workers=n_workers) as ex:
            for sid in sub_ids:
                ex.submit(worker, sid)

            done = 0
            while done < len(sub_ids):
                # Drain log queue first
                while not log_q.empty():
                    try:
                        yield log(log_q.get_nowait())
                    except Exception:
                        pass
                try:
                    etype, data = result_q.get(timeout=2)
                    done += 1
                    ping_count = 0  # reset on progress
                    if etype == "result":
                        accumulated.append(data)
                    yield evt({"type": etype, "data": data, "completed": done, "total": len(sub_ids)})
                    # Drain logs after each result
                    while not log_q.empty():
                        try:
                            yield log(log_q.get_nowait())
                        except Exception:
                            pass
                except queue_module.Empty:
                    ping_count += 1
                    elapsed = int(_time.time() - scan_start)

                    # Log progress every 15 seconds
                    if ping_count % 8 == 0:
                        ts_now = __import__('datetime').datetime.now().strftime('%H:%M:%S')
                        remaining = len(sub_ids) - done
                        yield log(f"[{ts_now}] Still waiting... {done}/{len(sub_ids)} subscriptions done, {remaining} pending ({elapsed}s elapsed)")

                    yield evt({"type": "ping"})

                    # Hard timeout - don't hang forever
                    if elapsed > MAX_TOTAL_WAIT:
                        ts_now = __import__('datetime').datetime.now().strftime('%H:%M:%S')
                        yield log(f"[{ts_now}] ⚠️ Scan timeout after {elapsed}s. Showing partial results.")
                        yield evt({"type": "error", "data": {
                            "subscription_id": "timeout",
                            "subscription_name": "Timeout",
                            "error": f"Scan timed out after {elapsed}s"
                        }, "completed": done, "total": len(sub_ids)})
                        break

                    # Drain logs on ping too
                    while not log_q.empty():
                        try:
                            yield log(log_q.get_nowait())
                        except Exception:
                            pass

        ts_final = __import__('datetime').datetime.now().strftime('%H:%M:%S')
        yield log(f"[{ts_final}] All subscriptions scanned. Building agent context...")

        _LAST_SCAN_CONTEXT["context"] = _build_scan_context(accumulated)
        _LAST_SCAN_CONTEXT["tenant_id"] = tenant_id
        _LAST_SCAN_CONTEXT["sub_ids"] = sub_ids

        yield log(f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}] Done.")
        yield evt({"type": "done"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Azure OpenAI discovery route
# ---------------------------------------------------------------------------

@app.route("/api/openai/discover")
def discover_openai():
    """
    Scan all subscriptions the signed-in user has access to and return
    all Azure OpenAI accounts + their chat-capable deployments.
    """
    tenant_id = request.args.get("tenant_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
        subs = auth_manager.list_subscriptions(credential)

        results = []
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def scan_sub(sub):
            found = []
            try:
                from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
                cs = CognitiveServicesManagementClient(credential, sub["id"])
                for acct in cs.accounts.list():
                    if (acct.kind or "").lower() != "openai":
                        continue
                    endpoint = (acct.properties.endpoint or "").rstrip("/") + "/"
                    try:
                        deps = list(cs.deployments.list(
                            resource_group_name=acct.id.split("/resourceGroups/")[1].split("/")[0],
                            account_name=acct.name,
                        ))
                        chat_deps = [
                            d.name for d in deps
                            if d.name and (
                                "gpt" in (d.name or "").lower()
                                or "gpt" in ((d.properties.model.name if d.properties and d.properties.model else "") or "").lower()
                            )
                        ]
                        if chat_deps:
                            found.append({
                                "account_name": acct.name,
                                "endpoint": endpoint,
                                "location": acct.location,
                                "subscription_name": sub["name"],
                                "subscription_id": sub["id"],
                                "deployments": chat_deps,
                            })
                    except Exception:
                        pass
            except Exception:
                pass
            return found

        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(scan_sub, s): s for s in subs}
            for f in as_completed(futures):
                results.extend(f.result())

        if results:
            return jsonify({"status": "ok", "resources": results})
        else:
            return jsonify({
                "status": "none",
                "message": "No Azure OpenAI resources with GPT deployments found in your subscriptions.",
                "portal_url": "https://portal.azure.com/#create/Microsoft.CognitiveServicesOpenAI",
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Drill-down: non-compliant resources for a specific assignment
# ---------------------------------------------------------------------------

@app.route("/api/drilldown/resources", methods=["POST"])
def drilldown_resources():
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    subscription_id = data.get("subscription_id", "").strip()
    assignment_id = data.get("assignment_id", "").strip()

    if not subscription_id:
        sub_ids = _LAST_SCAN_CONTEXT.get("sub_ids", [])
        subscription_id = sub_ids[0] if sub_ids else ""

    if not assignment_id:
        return jsonify({"status": "error", "message": "assignment_id required"}), 400

    try:
        credential = auth_manager.get_credential(tenant_id)
        fetcher = PolicyFetcher(credential)
        resources = fetcher.get_non_compliant_resources(subscription_id, assignment_id, top=50)
        return jsonify({"status": "ok", "resources": resources, "count": len(resources)})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Upgrade assignment effect: Audit → Deny
# ---------------------------------------------------------------------------

@app.route("/api/assignment/upgrade-effect", methods=["POST"])
def upgrade_assignment_effect():
    """
    Creates a new assignment with Deny effect and optionally deletes the Audit one.
    """
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    subscription_id = data.get("subscription_id", "").strip()
    old_assignment = data.get("assignment", {})
    new_effect = data.get("new_effect", "Deny")

    if not subscription_id:
        sub_ids = _LAST_SCAN_CONTEXT.get("sub_ids", [])
        subscription_id = sub_ids[0] if sub_ids else ""

    try:
        credential = auth_manager.get_credential(tenant_id)
        from azure.mgmt.resource import PolicyClient
        import re, uuid, json as _json

        client = PolicyClient(credential=credential, subscription_id=subscription_id)

        # Build new parameters with effect updated
        params = old_assignment.get("parameters", {}) or {}
        new_params = {}
        for k, v in params.items():
            if "effect" in k.lower():
                new_params[k] = {"value": new_effect}
            elif isinstance(v, dict):
                new_params[k] = v
            else:
                new_params[k] = {"value": v}

        if not new_params and "effect" not in str(params).lower():
            # Policy might have effect as param named differently
            new_params = dict(params)
            new_params["effect"] = {"value": new_effect}

        # Check if managed identity needed
        def_id = old_assignment.get("policy_definition_id", "")
        def_name = def_id.rstrip("/").split("/")[-1]
        needs_id = False
        try:
            if def_id.startswith("/subscriptions/"):
                p = client.policy_definitions.get(def_name)
            else:
                p = client.policy_definitions.get_built_in(def_name)
            rule_str = _json.dumps(p.policy_rule, default=str).lower() if p.policy_rule else ""
            needs_id = "deployifnotexists" in rule_str or '"modify"' in rule_str
        except Exception:
            pass

        new_name = re.sub(r"[^a-zA-Z0-9\-]", "-", old_assignment.get("display_name", ""))[:60].strip("-") + "-deny"

        props = {
            "policy_definition_id": def_id,
            "display_name": old_assignment.get("display_name", "")[:128] + " (Deny)",
            "enforcement_mode": "Default",
            "parameters": new_params if new_params else None,
        }
        if props["parameters"] is None:
            del props["parameters"]
        if needs_id:
            props["location"] = "westeurope"
            props["identity"] = {"type": "SystemAssigned"}

        scope = old_assignment.get("scope", f"/subscriptions/{subscription_id}")
        result = client.policy_assignments.create(scope, new_name[:64], props)

        # Delete old Audit assignment
        old_scope = old_assignment.get("scope", scope)
        old_name = old_assignment.get("name", "")
        deleted = False
        if old_name and data.get("delete_old", True):
            try:
                client.policy_assignments.delete(old_scope, old_name)
                deleted = True
            except Exception as e:
                print(f"  [warn] could not delete old assignment: {e}")

        return jsonify({
            "status": "ok",
            "new_assignment_id": result.id,
            "old_deleted": deleted,
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------------------------------------------------------------------------
# Auto-fix routes
# ---------------------------------------------------------------------------

@app.route("/api/autofix/preview", methods=["POST"])
def autofix_preview():
    """
    Preview what an auto-fix assignment would look like:
    fetch built-in policy parameter definitions and map from existing custom assignment params.
    """
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    subscription_id = data.get("subscription_id", "").strip()
    builtin_policy_id = data.get("builtin_policy_id", "").strip()
    custom_assignment = data.get("custom_assignment", {})  # existing assignment dict
    custom_policy = data.get("custom_policy", {})

    if not subscription_id:
        sub_ids = _LAST_SCAN_CONTEXT.get("sub_ids", [])
        subscription_id = sub_ids[0] if sub_ids else ""

    try:
        credential = auth_manager.get_credential(tenant_id)
        from azure.mgmt.resource import PolicyClient
        client = PolicyClient(credential=credential, subscription_id=subscription_id)

        # Get built-in policy details
        builtin_name = builtin_policy_id.rstrip("/").split("/")[-1]
        builtin = client.policy_definitions.get_built_in(builtin_name)
        import json as _json
        from modules.fetcher import _safe_dict
        builtin_params_def = _safe_dict(builtin.parameters) or {}

        # Existing custom assignment parameters (values already set)
        existing_params = custom_assignment.get("parameters", {}) or {}

        # Map: try exact name match first, then fuzzy (lowercase contains)
        mapped_params = {}
        unmapped_builtin = []
        def _param_meta(bp_def):
            if not isinstance(bp_def, dict):
                return {"type": "String", "allowed": None, "default": None, "description": ""}
            allowed = bp_def.get("allowedValues")
            default = bp_def.get("defaultValue")
            description = (bp_def.get("metadata") or {}).get("description", "")
            display_name = (bp_def.get("metadata") or {}).get("displayName", "")
            return {
                "type": bp_def.get("type", "String"),
                "allowed": allowed,
                "default": default,
                "description": description or display_name,
            }

        for bp_name, bp_def in builtin_params_def.items():
            meta = _param_meta(bp_def)
            if bp_name in existing_params:
                mapped_params[bp_name] = {
                    "value": existing_params[bp_name].get("value"),
                    "source": "exact_match",
                    **meta,
                }
            else:
                fuzzy = next(
                    (k for k in existing_params
                     if bp_name.lower() in k.lower() or k.lower() in bp_name.lower()),
                    None
                )
                if fuzzy:
                    mapped_params[bp_name] = {
                        "value": existing_params[fuzzy].get("value"),
                        "source": f"fuzzy_match:{fuzzy}",
                        **meta,
                    }
                elif meta["default"] is not None:
                    mapped_params[bp_name] = {
                        "value": meta["default"],
                        "source": "default",
                        **meta,
                    }
                else:
                    unmapped_builtin.append({
                        "name": bp_name,
                        **meta,
                    })

        # Proposed new assignment
        proposed_scope = custom_assignment.get("scope") or f"/subscriptions/{subscription_id}"
        proposed_name = (custom_assignment.get("display_name") or custom_policy.get("display_name") or builtin.display_name or "")
        proposed_name = proposed_name[:100] + " (Built-in)" if len(proposed_name) < 100 else proposed_name[:108] + " [BIn]"

        # Detect if built-in needs managed identity
        rule_str = ""
        try:
            import json as _json
            rule_str = _json.dumps(builtin.policy_rule, default=str).lower() if builtin.policy_rule else ""
        except Exception:
            pass
        needs_identity = "deployifnotexists" in rule_str or '"modify"' in rule_str

        return jsonify({
            "status": "ok",
            "builtin_display_name": builtin.display_name,
            "builtin_description": builtin.description or "",
            "proposed_scope": proposed_scope,
            "proposed_display_name": proposed_name,
            "mapped_params": mapped_params,
            "unmapped_params": unmapped_builtin,
            "builtin_policy_id": f"/providers/Microsoft.Authorization/policyDefinitions/{builtin_name}",
            "needs_identity": needs_identity,
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/autofix/execute", methods=["POST"])
def autofix_execute():
    """Create the new built-in assignment and optionally delete the old custom one."""
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    subscription_id = data.get("subscription_id", "").strip()
    builtin_policy_id = data.get("builtin_policy_id", "").strip()
    scope = data.get("scope", "").strip()
    display_name = data.get("display_name", "").strip()
    parameters = data.get("parameters", {})  # {name: value}
    delete_old_assignment = data.get("delete_old_assignment", False)
    old_assignment_scope = data.get("old_assignment_scope", "")
    old_assignment_name = data.get("old_assignment_name", "")

    if not subscription_id:
        sub_ids = _LAST_SCAN_CONTEXT.get("sub_ids", [])
        subscription_id = sub_ids[0] if sub_ids else ""

    try:
        credential = auth_manager.get_credential(tenant_id)
        from modules.policy_actions import assign_policy, delete_assignment
        from azure.mgmt.resource import PolicyClient
        import re, uuid, json as _json

        safe_name = re.sub(r"[^a-zA-Z0-9\-]", "-", display_name)[:64].strip("-") or "autofix-" + str(uuid.uuid4())[:8]

        # Check if the built-in policy requires a managed identity (DeployIfNotExists / Modify)
        needs_identity = False
        location = "westeurope"
        try:
            pc = PolicyClient(credential=credential, subscription_id=subscription_id)
            builtin_name = builtin_policy_id.rstrip("/").split("/")[-1]
            builtin_def = pc.policy_definitions.get_built_in(builtin_name)
            rule_str = _json.dumps(builtin_def.policy_rule, default=str).lower() if builtin_def.policy_rule else ""
            needs_identity = "deployifnotexists" in rule_str or '"modify"' in rule_str
        except Exception as e:
            print(f"  [warn] could not check built-in policy rule: {e}")

        result = assign_policy(
            credential=credential,
            subscription_id=subscription_id,
            policy_definition_id=builtin_policy_id,
            scope=scope,
            display_name=display_name,
            parameters={k: v for k, v in parameters.items() if v is not None and v != ""},
            needs_identity=needs_identity,
            location=location,
        )

        deleted = False
        if delete_old_assignment and old_assignment_name and old_assignment_scope:
            try:
                delete_assignment(credential, subscription_id, old_assignment_scope, old_assignment_name)
                deleted = True
            except Exception as de:
                print(f"  [warn] could not delete old assignment: {de}")

        return jsonify({
            "status": "ok",
            "new_assignment": result,
            "old_deleted": deleted,
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Agent routes
# ---------------------------------------------------------------------------

@app.route("/api/agent/chat", methods=["POST"])
def agent_chat():
    data = request.json or {}
    api_key = data.get("api_key", "").strip()
    api_type = data.get("api_type", "openai")
    azure_endpoint = data.get("azure_endpoint", "").strip()
    azure_deployment = data.get("azure_deployment", "").strip()
    tenant_id = data.get("tenant_id", "").strip()
    messages = data.get("messages", [])

    if api_type == "azure-credential":
        credential = auth_manager.get_credential(tenant_id)
    elif not api_key:
        return jsonify({"status": "error", "message": "API key required"}), 400
    else:
        credential = None

    from modules.agent import chat as agent_chat_fn
    scan_ctx = _LAST_SCAN_CONTEXT.get("context", "")

    result = agent_chat_fn(
        messages=messages,
        api_key=api_key or None,
        api_type=api_type,
        azure_endpoint=azure_endpoint or None,
        azure_deployment=azure_deployment or None,
        scan_context=scan_ctx,
        credential=credential,
    )
    return jsonify({"status": "ok", **result})


@app.route("/api/agent/execute", methods=["POST"])
def agent_execute():
    """Execute a confirmed action."""
    data = request.json or {}
    action_type = data.get("action_type", "")
    action_params = data.get("action_params", {})
    tenant_id = data.get("tenant_id", "").strip()
    subscription_id = data.get("subscription_id", "").strip()

    if not subscription_id:
        sub_ids = _LAST_SCAN_CONTEXT.get("sub_ids", [])
        subscription_id = sub_ids[0] if sub_ids else ""

    if not subscription_id:
        return jsonify({"status": "error", "message": "No subscription available. Please run a scan first."}), 400

    try:
        credential = auth_manager.get_credential(tenant_id)
        from modules.policy_actions import (
            assign_policy, create_custom_policy,
            trigger_remediation,
        )

        if action_type == "assign_policy":
            result = assign_policy(
                credential=credential,
                subscription_id=subscription_id,
                policy_definition_id=action_params["policy_definition_id"],
                scope=action_params["scope"],
                display_name=action_params["display_name"],
                parameters=action_params.get("parameters"),
            )
            return jsonify({"status": "ok", "action_type": action_type, "result": result})

        elif action_type == "create_custom_policy":
            result = create_custom_policy(
                credential=credential,
                subscription_id=subscription_id,
                definition=action_params["definition"],
            )
            return jsonify({"status": "ok", "action_type": action_type, "result": result})

        elif action_type == "remediate":
            result = trigger_remediation(
                credential=credential,
                subscription_id=subscription_id,
                assignment_id=action_params["assignment_id"],
            )
            return jsonify({"status": "ok", "action_type": action_type, "result": result})

        else:
            return jsonify({"status": "error", "message": f"Unknown action: {action_type}"}), 400

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("  Azure Policy Analyzer")
    print("=" * 50)
    print("Open http://localhost:5000 in your browser\n")
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)
