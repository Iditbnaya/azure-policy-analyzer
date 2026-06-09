import sys
import os
import uuid

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.auth import AuthManager
from modules.fetcher import PolicyFetcher
from modules.analyzer import PolicyAnalyzer
from modules.recommender import PolicyRecommender

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

auth_manager = AuthManager()


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


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json or {}
    subscription_ids = data.get("subscription_ids", [])
    tenant_id = data.get("tenant_id", "").strip()
    subscription_names = data.get("subscription_names", {})

    if not subscription_ids:
        return jsonify({"status": "error", "message": "No subscriptions selected"}), 400

    try:
        credential = auth_manager.get_credential(tenant_id)
        fetcher = PolicyFetcher(credential)
        analyzer = PolicyAnalyzer()
        recommender = PolicyRecommender()

        # Fetch built-in policies once (shared across subscriptions)
        print("Fetching built-in policies (this may take a moment)...")
        builtin_policies = fetcher.get_builtin_policies(subscription_ids[0])
        print(f"  - {len(builtin_policies)} built-in policies loaded")

        results = []
        for sub_id in subscription_ids:
            print(f"\nScanning subscription: {sub_id}")

            compliance = fetcher.get_compliance_summary(sub_id)
            print(f"  - {len(compliance)} non-compliant assignments")

            custom_policies = fetcher.get_custom_policies(sub_id)
            print(f"  - {len(custom_policies)} custom policies")

            assignments = fetcher.get_policy_assignments(sub_id)
            print(f"  - {len(assignments)} policy assignments")

            analyzed = analyzer.analyze(custom_policies, assignments, compliance)

            recommendations = recommender.get_recommendations(
                analyzed["problematic"], builtin_policies
            )
            print(f"  - {len(recommendations)} recommendations generated")

            results.append({
                "subscription_id": sub_id,
                "subscription_name": subscription_names.get(sub_id, sub_id),
                "compliance": compliance,
                "custom_policies": {
                    "stats": analyzed["stats"],
                    "all": analyzed["all"],
                    "problematic": analyzed["problematic"],
                },
                "recommendations": recommendations,
            })

        print("\nScan complete.")
        return jsonify({"status": "ok", "results": results})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("  Azure Policy Analyzer")
    print("=" * 50)
    print("Open http://localhost:5000 in your browser\n")
    app.run(debug=False, host="127.0.0.1", port=5000)
