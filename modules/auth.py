from azure.identity import InteractiveBrowserCredential
from azure.mgmt.subscription import SubscriptionClient


class AuthManager:
    """Manages Azure authentication using interactive browser login."""

    def __init__(self):
        self._credentials = {}

    def get_credential(self, tenant_id: str = "") -> InteractiveBrowserCredential:
        key = tenant_id.strip() or "default"
        if key not in self._credentials:
            kwargs = {}
            if tenant_id.strip():
                kwargs["tenant_id"] = tenant_id.strip()
            self._credentials[key] = InteractiveBrowserCredential(**kwargs)
        return self._credentials[key]

    def list_subscriptions(self, credential) -> list:
        client = SubscriptionClient(credential)
        result = []
        for sub in client.subscriptions.list():
            state = sub.state
            if hasattr(state, "value"):
                state = state.value
            result.append({
                "id": sub.subscription_id,
                "name": sub.display_name,
                "state": state or "Unknown",
            })
        return result
