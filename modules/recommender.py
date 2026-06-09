import re
from difflib import SequenceMatcher


class PolicyRecommender:
    """Matches problematic custom policies to built-in alternatives."""

    def get_recommendations(self, problematic_policies: list, builtin_policies: list) -> list:
        if not problematic_policies or not builtin_policies:
            return []

        recommendations = []
        for policy in problematic_policies:
            matches = self._find_matches(policy, builtin_policies)
            if matches:
                recommendations.append({
                    "custom_policy": {
                        "id": policy.get("id", ""),
                        "name": policy.get("name", ""),
                        "display_name": policy.get("display_name", ""),
                        "effect": policy.get("effect", ""),
                        "category": policy.get("category", ""),
                        "issue_count": policy.get("issue_count", 0),
                        "warning_count": policy.get("warning_count", 0),
                    },
                    "matches": matches[:3],
                })
        return recommendations

    def _find_matches(self, custom: dict, builtins: list) -> list:
        scored = []

        c_name = custom.get("display_name", "").lower()
        c_desc = custom.get("description", "").lower()
        c_cat = custom.get("category", "").lower()
        c_effect = custom.get("effect", "").lower()
        c_words = {w for w in re.findall(r'\w+', c_name + " " + c_desc) if len(w) > 3}

        for b in builtins:
            score = 0
            b_name = b.get("display_name", "").lower()
            b_cat = b.get("category", "").lower()
            b_effect = b.get("effect", "").lower()
            b_words = {w for w in re.findall(r'\w+', b_name + " " + b.get("description", "").lower()) if len(w) > 3}

            # Category match
            if c_cat and b_cat:
                if c_cat == b_cat:
                    score += 40
                elif c_cat in b_cat or b_cat in c_cat:
                    score += 20

            # Effect match
            if c_effect and b_effect and c_effect not in ("parameterized", "unknown"):
                if c_effect == b_effect:
                    score += 20
                else:
                    score += 3

            # Word overlap
            if c_words and b_words:
                overlap = len(c_words & b_words) / max(len(c_words), 1)
                score += int(overlap * 40)

            # Name similarity
            if c_name and b_name:
                sim = SequenceMatcher(None, c_name, b_name).ratio()
                score += int(sim * 20)

            if score >= 30:
                scored.append({
                    **b,
                    "match_score": min(99, score),
                    "match_reason": self._explain(custom, b, score),
                })

        return sorted(scored, key=lambda x: x["match_score"], reverse=True)

    def _explain(self, custom: dict, builtin: dict, score: int) -> str:
        reasons = []
        if custom.get("category", "").lower() == builtin.get("category", "").lower() and custom.get("category"):
            reasons.append(f"Same category: {builtin.get('category', '')}")
        ce = custom.get("effect", "").lower()
        be = builtin.get("effect", "").lower()
        if ce and be and ce == be and ce not in ("parameterized", "unknown"):
            reasons.append(f"Same effect: {builtin.get('effect', '')}")
        if score >= 65:
            reasons.append("High name/description similarity")
        elif score >= 45:
            reasons.append("Moderate keyword overlap")
        return "; ".join(reasons) if reasons else "Partial match based on category and keywords"
