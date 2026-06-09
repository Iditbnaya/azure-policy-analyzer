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

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

auth_manager = AuthManager()
pending_scans = {}  # scan_id -> params


def _scan_subscription(sub_id: str, sub_name: str, credential, builtin_policies: list) -> dict:
    """Scan one subscription with parallelized inner API calls (compliance + custom + assignments run concurrently)."""
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


# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------

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
    """Return management group hierarchy for the authenticated tenant."""
    tenant_id = request.args.get("tenant_id", "").strip()
    try:
        credential = auth_manager.get_credential(tenant_id)
        fetcher = PolicyFetcher(credential)
        tree = fetcher.get_management_group_tree(tenant_id or None)
        return jsonify({"status": "ok", "tree": tree})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/scan/init", methods=["POST"])
def scan_init():
    """Store scan params server-side and return a scan_id for the SSE stream."""
    scan_id = str(uuid.uuid4())
    pending_scans[scan_id] = request.json or {}
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/stream/<scan_id>")
def scan_stream_route(scan_id):
    """
    SSE endpoint - streams per-subscription results as they complete.
    Subscriptions are scanned in parallel (up to 5 at a time).
    Each subscription's internal calls (compliance/custom/assignments) are also parallel.
    """
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

        # Step 1: Load built-in policies once (reused for all subscriptions)
        builtins = []
        try:
            yield evt({"type": "progress", "msg": "Loading built-in policies..."})
            fetcher = PolicyFetcher(credential)
            builtins = fetcher.get_builtin_policies(sub_ids[0])
            yield evt({"type": "builtins", "count": len(builtins)})
        except Exception as e:
            yield evt({"type": "progress", "msg": f"Built-ins unavailable: {e}"})

        # Step 2: Scan all subscriptions in parallel, stream results as they arrive
        result_q = queue_module.Queue()

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
                    yield evt({
                        "type": etype,
                        "data": data,
                        "completed": done,
                        "total": len(sub_ids),
                    })
                except queue_module.Empty:
                    yield evt({"type": "ping"})

        yield evt({"type": "done"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    print("=" * 50)
    print("  Azure Policy Analyzer")
    print("=" * 50)
    print("Open http://localhost:5000 in your browser\n")
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)
