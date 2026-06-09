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

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_comp = ex.submit(fetcher.get_compliance_summary, sub_id)
        f_custom = ex.submit(fetcher.get_custom_policies, sub_id)
        f_assign = ex.submit(fetcher.get_policy_assignments, sub_id)
        compliance = f_comp.result()
        custom_policies = f_custom.result()
        assignments = f_assign.result()

    analyzed = analyzer.analyze(custom_policies, assignments, compliance)
    recs = recommender.get_recommendations(analyzed["problematic"], builtin_policies)

    return {
        "subscription_id": sub_id,
        "subscription_name": sub_name,
        "compliance": compliance,
        "custom_policies": {
            "stats": analyzed["stats"],
            "all": analyzed["all"],
            "problematic": analyzed["problematic"],
        },
        "recommendations": recs,
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

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/connect", methods=["POST"])
def connect():
    data = request.json or {}
    tenant_id = data.get("tenant_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
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

        yield evt({"type": "start", "total": len(sub_ids)})

        # Load built-in policies from cache (fast)
        yield evt({"type": "progress", "msg": "Loading built-in policies from cache..."})
        builtins, cache_source = policy_cache.get(credential, sub_ids[0])
        yield evt({"type": "builtins", "count": len(builtins), "cache_source": cache_source})

        # Scan subscriptions in parallel, stream results
        result_q = queue_module.Queue()
        accumulated = []

        def worker(sid):
            sname = sub_names.get(sid, sid)
            try:
                res = _scan_subscription(sid, sname, credential, builtins)
                result_q.put(("result", res))
            except Exception as e:
                import traceback
                traceback.print_exc()
                result_q.put(("error", {
                    "subscription_id": sid,
                    "subscription_name": sname,
                    "error": str(e),
                }))

        n_workers = min(5, len(sub_ids))
        with ThreadPoolExecutor(max_workers=n_workers) as ex:
            for sid in sub_ids:
                ex.submit(worker, sid)

            done = 0
            while done < len(sub_ids):
                try:
                    etype, data = result_q.get(timeout=120)
                    done += 1
                    if etype == "result":
                        accumulated.append(data)
                    yield evt({"type": etype, "data": data,
                               "completed": done, "total": len(sub_ids)})
                except queue_module.Empty:
                    yield evt({"type": "ping"})

        # Save scan context for agent
        _LAST_SCAN_CONTEXT["context"] = _build_scan_context(accumulated)
        _LAST_SCAN_CONTEXT["tenant_id"] = tenant_id
        _LAST_SCAN_CONTEXT["sub_ids"] = sub_ids

        yield evt({"type": "done"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
