"""
CROA Reference Harness — Action Parameter Schema Registry
Normative Reference: CROA Framework v1.0.1 §4.5.1 / §4.9.1

Maintains canonical action parameter schemas and validates request parameters.
Operates against an explicit registry without embedded domain knowledge.
Fails closed on unregistered actions or schema contract violations.
"""

from typing import Dict, Any, Set, Tuple, Optional

class ActionSchemaRegistry:
    def __init__(self):
        self._schemas: Dict[str, Dict[str, Set[str]]] = {}

    def register_schema(self, action: str, allowed_keys: Set[str], required_keys: Optional[Set[str]] = None) -> None:
        """Registers a canonical parameter contract for an action."""
        self._schemas[action] = {
            "allowed_keys": set(allowed_keys),
            "required_keys": set(required_keys or set())
        }

    def unregister_schema(self, action: str) -> None:
        """Removes an action schema from the registry."""
        self._schemas.pop(action, None)

    def get_schema(self, action: str) -> Optional[Dict[str, Set[str]]]:
        """Retrieves registered schema for an action."""
        return self._schemas.get(action)

    def is_registered(self, action: str) -> bool:
        """Returns True if the action has a registered schema contract."""
        return action in self._schemas

    def clear(self) -> None:
        """Clears all registered schemas."""
        self._schemas.clear()

    def validate_action_parameters(
        self,
        action: str,
        parameters: Optional[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Validates incoming request parameters against the registered action schema contract.
        Fails closed with explicit reason code if unregistered or invalid.
        """
        schema = self._schemas.get(action)
        if not schema:
            return False, f"UNREGISTERED_ACTION_SCHEMA: Action '{action}' has no registered parameter contract"

        params = parameters or {}
        if not isinstance(params, dict):
            return False, f"SCHEMA_VIOLATION: Parameters for action '{action}' must be a dictionary"

        param_keys = set(params.keys())

        extra_keys = param_keys - schema["allowed_keys"]
        if extra_keys:
            return False, f"SCHEMA_VIOLATION: Unexpected parameters {sorted(list(extra_keys))} not permitted for action '{action}'"

        missing_keys = schema["required_keys"] - param_keys
        if missing_keys:
            return False, f"SCHEMA_VIOLATION: Missing required parameters {sorted(list(missing_keys))} for action '{action}'"

        return True, "VALID"

# Global default schema registry instance
default_schema_registry = ActionSchemaRegistry()

# Register generic baseline reference actions
default_schema_registry.register_schema("get_resource", allowed_keys={"resource_id"}, required_keys=set())
default_schema_registry.register_schema("export_records", allowed_keys={"count", "format", "include_pii"}, required_keys=set())
default_schema_registry.register_schema("change_config", allowed_keys={"setting", "value"}, required_keys=set())
default_schema_registry.register_schema("deploy_service", allowed_keys={"version", "rollback_on_failure", "units"}, required_keys=set())
default_schema_registry.register_schema("delete_resource", allowed_keys={"resource_id", "force"}, required_keys=set())
default_schema_registry.register_schema("get_customer", allowed_keys={"customer_id"}, required_keys=set())
default_schema_registry.register_schema("export_customers", allowed_keys={"count", "format", "include_pii"}, required_keys=set())
default_schema_registry.register_schema("delete_environment", allowed_keys={"environment_id", "force"}, required_keys=set())

def validate_action_parameters(action: str, parameters: Optional[Dict[str, Any]], registry: Optional[ActionSchemaRegistry] = None) -> Tuple[bool, str]:
    """Helper delegating to specified registry or global default."""
    reg = registry or default_schema_registry
    return reg.validate_action_parameters(action, parameters)
