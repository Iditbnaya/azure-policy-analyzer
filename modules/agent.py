"""
Policy chat agent using OpenAI (or Azure OpenAI) tool/function calling.

Tools:
  - generate_policy_json        SAFE  - returns JSON in chat, no Azure changes
  - request_assign_policy       WARNING/DANGER - returns confirmation request
  - request_create_custom_policy WARNING - returns confirmation request
  - request_remediate           WARNING/DANGER - returns confirmation request

Dangerous tools never touch Azure directly; they return confirmation_required
dicts that the frontend shows in a modal. On user confirm, /api/agent/execute is called.
"""

import json
import re
from modules.policy_actions import assess_danger

SYSTEM_PROMPT = """You are an Azure Policy Expert assistant embedded in the Azure Policy Analyzer tool.

You help users:
1. Understand Azure Policy concepts, effects, aliases, modes, and best practices
2. Write complete, production-ready Azure Policy definition JSON
3. Diagnose why a custom policy is broken and how to fix it
4. Find the right built-in policy to replace a custom one
5. Assign policies to scopes (subscription, resource group, management group)
6. Trigger policy remediation for non-compliant resources

BEHAVIOR RULES:
- For questions, explanations, and JSON generation: answer directly in Markdown
- When writing policy JSON: always include policyRule (if/then blocks), metadata.category, mode, and parameters if needed. Return it as a code block AND call the generate_policy_json tool so the UI renders it with a copy/deploy button.
- For ANY action that modifies Azure resources (assign, create, remediate, delete):
  * Always call the appropriate request_* tool - never skip the confirmation step
  * Before calling the tool, explain in your message text what you are about to request
  * NEVER say you have completed an action unless it was confirmed and executed
- Always tell the user what WILL happen and why it might be risky before or alongside the confirmation request

DANGER LEVEL GUIDE:
- SAFE: reading data, explaining things, generating JSON
- WARNING: Audit assignments, creating custom policies, resource-group scope
- DANGER: Deny/DenyAction effect on any scope, subscription or MG scope assignments, remediating >10 resources

Current scan context will be injected when available.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "generate_policy_json",
            "description": (
                "Generate a complete Azure Policy definition JSON. "
                "SAFE - only produces JSON in the UI, does NOT create anything in Azure."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "display_name": {"type": "string"},
                    "description": {"type": "string"},
                    "category": {"type": "string"},
                    "mode": {"type": "string", "default": "All"},
                    "effect": {"type": "string"},
                    "policy_rule": {
                        "type": "object",
                        "description": "Policy rule with 'if' condition and 'then' effect blocks",
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Policy parameters definition",
                    },
                },
                "required": ["display_name", "policy_rule"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_assign_policy",
            "description": (
                "Request to assign an Azure policy to a scope. "
                "Returns a confirmation request to the user - does NOT assign yet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "policy_definition_id": {
                        "type": "string",
                        "description": "Full resource ID of the policy definition",
                    },
                    "scope": {
                        "type": "string",
                        "description": "Assignment scope (e.g. /subscriptions/{id} or /subscriptions/{id}/resourceGroups/{rg})",
                    },
                    "display_name": {"type": "string", "description": "Assignment display name"},
                    "effect": {
                        "type": "string",
                        "description": "The policy effect - used for danger assessment",
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Assignment parameters as key-value pairs",
                    },
                    "explanation": {
                        "type": "string",
                        "description": "Why this assignment is being requested",
                    },
                    "what_will_happen": {
                        "type": "string",
                        "description": "Detailed description of impact: affected resources, compliance behavior, side effects",
                    },
                },
                "required": [
                    "policy_definition_id", "scope", "display_name",
                    "effect", "explanation", "what_will_happen",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_create_custom_policy",
            "description": (
                "Request to create a new custom policy definition in the subscription. "
                "Returns a confirmation request - does NOT create yet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "definition": {
                        "type": "object",
                        "description": "Complete Azure Policy definition object (with properties.policyRule etc.)",
                    },
                    "explanation": {"type": "string"},
                    "what_will_happen": {"type": "string"},
                },
                "required": ["definition", "explanation", "what_will_happen"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_remediate",
            "description": (
                "Request to trigger policy remediation for a policy assignment. "
                "Returns a confirmation request - does NOT remediate yet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assignment_id": {
                        "type": "string",
                        "description": "Full resource ID of the policy assignment",
                    },
                    "assignment_name": {"type": "string"},
                    "non_compliant_count": {
                        "type": "integer",
                        "description": "Number of non-compliant resources (for danger assessment)",
                    },
                    "explanation": {"type": "string"},
                    "what_will_happen": {"type": "string"},
                },
                "required": ["assignment_id", "explanation", "what_will_happen"],
            },
        },
    },
]


def _handle_tool(name: str, args: dict) -> dict:
    if name == "generate_policy_json":
        slug = re.sub(r"[^a-z0-9-]", "-", args.get("display_name", "custom-policy").lower())[:64]
        policy = {
            "name": slug,
            "properties": {
                "displayName": args.get("display_name", ""),
                "description": args.get("description", ""),
                "policyType": "Custom",
                "mode": args.get("mode", "All"),
                "metadata": {"category": args.get("category", "Custom")},
                "parameters": args.get("parameters", {}),
                "policyRule": args.get("policy_rule", {}),
            },
        }
        return {"type": "policy_json", "json": policy}

    elif name == "request_assign_policy":
        effect = args.get("effect", "")
        scope = args.get("scope", "")
        level, reasons = assess_danger(effect, scope)
        return {
            "type": "confirmation_required",
            "action_type": "assign_policy",
            "danger_level": level,
            "danger_reasons": reasons,
            "explanation": args.get("explanation", ""),
            "what_will_happen": args.get("what_will_happen", ""),
            "action_params": {
                "policy_definition_id": args.get("policy_definition_id", ""),
                "scope": scope,
                "display_name": args.get("display_name", ""),
                "parameters": args.get("parameters", {}),
                "effect": effect,
            },
        }

    elif name == "request_create_custom_policy":
        defn = args.get("definition", {})
        props = defn.get("properties", defn)
        try:
            effect = props.get("policyRule", {}).get("then", {}).get("effect", "")
        except Exception:
            effect = ""
        level, reasons = assess_danger(effect, "subscription")
        if level == "SAFE":
            level = "WARNING"
            reasons = ["Creates a new custom policy definition in your Azure subscription"]
        return {
            "type": "confirmation_required",
            "action_type": "create_custom_policy",
            "danger_level": level,
            "danger_reasons": reasons,
            "explanation": args.get("explanation", ""),
            "what_will_happen": args.get("what_will_happen", ""),
            "action_params": {"definition": defn},
        }

    elif name == "request_remediate":
        nc = args.get("non_compliant_count", 0)
        level, reasons = assess_danger("", "", nc)
        if level == "SAFE":
            level = "WARNING"
            reasons = ["Remediation will modify Azure resources to bring them into compliance"]
        return {
            "type": "confirmation_required",
            "action_type": "remediate",
            "danger_level": level,
            "danger_reasons": reasons,
            "explanation": args.get("explanation", ""),
            "what_will_happen": args.get("what_will_happen", ""),
            "action_params": {
                "assignment_id": args.get("assignment_id", ""),
                "assignment_name": args.get("assignment_name", ""),
            },
        }

    return {"error": f"Unknown tool: {name}"}


def chat(messages: list, api_key: str = None, api_type: str = "openai",
         azure_endpoint: str = None, azure_deployment: str = None,
         azure_api_version: str = "2024-05-01-preview",
         scan_context: str = None, credential=None) -> dict:
    """
    Run one agent turn.
    Returns:
      {
        role: "assistant",
        content: str,            # Markdown text
        confirmations: list,     # pending confirmation requests
        policy_jsons: list,      # generated policy JSONs
      }
    """
    try:
        if api_type in ("azure", "azure-credential"):
            from openai import AzureOpenAI
            if api_type == "azure-credential" and credential:
                from azure.identity import get_bearer_token_provider
                token_provider = get_bearer_token_provider(
                    credential, "https://cognitiveservices.azure.com/.default"
                )
                client = AzureOpenAI(
                    azure_endpoint=azure_endpoint,
                    azure_ad_token_provider=token_provider,
                    api_version=azure_api_version,
                )
            else:
                client = AzureOpenAI(
                    api_key=api_key,
                    azure_endpoint=azure_endpoint,
                    api_version=azure_api_version,
                )
            model = azure_deployment or "gpt-4o"
        else:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            model = "gpt-4o"

        system_text = SYSTEM_PROMPT
        if scan_context:
            system_text += f"\n\n---\nCURRENT SCAN CONTEXT (use this to answer policy-specific questions):\n{scan_context}"

        all_msgs = [{"role": "system", "content": system_text}] + messages

        resp = client.chat.completions.create(
            model=model,
            messages=all_msgs,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=4096,
            temperature=0.2,
        )

        msg = resp.choices[0].message
        confirmations = []
        policy_jsons = []
        tool_msgs = []

        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    args = {}
                result = _handle_tool(tc.function.name, args)

                if result.get("type") == "confirmation_required":
                    confirmations.append(result)
                    tool_msgs.append({
                        "tool_call_id": tc.id,
                        "role": "tool",
                        "content": json.dumps({
                            "status": "confirmation_pending",
                            "action_type": result["action_type"],
                        }),
                    })
                elif result.get("type") == "policy_json":
                    policy_jsons.append(result["json"])
                    tool_msgs.append({
                        "tool_call_id": tc.id,
                        "role": "tool",
                        "content": json.dumps({
                            "status": "json_generated",
                            "name": result["json"].get("name", ""),
                        }),
                    })
                else:
                    tool_msgs.append({
                        "tool_call_id": tc.id,
                        "role": "tool",
                        "content": json.dumps(result),
                    })

            # Second pass to get the assistant's text response
            follow_msgs = all_msgs + [{"role": "assistant", "content": msg.content or "",
                                        "tool_calls": [
                                            {"id": tc.id, "type": "function",
                                             "function": {"name": tc.function.name,
                                                          "arguments": tc.function.arguments}}
                                            for tc in msg.tool_calls
                                        ]}] + tool_msgs
            resp2 = client.chat.completions.create(
                model=model,
                messages=follow_msgs,
                max_tokens=2048,
                temperature=0.2,
            )
            final_content = resp2.choices[0].message.content or ""
        else:
            final_content = msg.content or ""

        return {
            "role": "assistant",
            "content": final_content,
            "confirmations": confirmations,
            "policy_jsons": policy_jsons,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "role": "assistant",
            "content": f"**Agent error:** {e}",
            "confirmations": [],
            "policy_jsons": [],
        }
