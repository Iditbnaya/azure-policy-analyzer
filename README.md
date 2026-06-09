# Azure Policy Analyzer

A local web app that scans Azure subscriptions for custom policy issues and recommends built-in alternatives.

## What it does

**Compliance Issues tab** - Shows all non-compliant policy assignments (same view as Azure Portal).

**Custom Policy Health tab** - Analyzes every custom policy definition and flags:
- Policies not assigned anywhere (orphaned)
- Invalid or incorrectly-cased effects
- Old API version references in policy rules
- Missing descriptions or categories
- Malformed policy rule structure

**Recommendations tab** - For each problematic custom policy, suggests the best matching built-in policies that could replace it - saving you from maintenance and definition drift.

## Requirements

- Python 3.9+
- Azure account with at least **Reader** role on the subscriptions you want to scan

## Quick Start

**Windows:**
```
double-click run.bat
```

**Manual:**
```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000 in your browser.

## Authentication

The app uses **Interactive Browser login** - when you click "Connect to Azure", a browser window opens for Microsoft sign-in. No client secrets needed.

Optionally enter a Tenant ID if you have multiple Azure AD tenants.

## Required Permissions

The signed-in user needs at minimum:
- `Microsoft.PolicyInsights/policyStates/summarize/action` - for compliance data
- `Microsoft.Authorization/policyDefinitions/read` - for policy definitions
- `Microsoft.Authorization/policyAssignments/read` - for assignments

These are all included in the built-in **Reader** role.
