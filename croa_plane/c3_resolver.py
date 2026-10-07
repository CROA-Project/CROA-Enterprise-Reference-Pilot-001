"""
CROA Reference Harness — C3 Context Resolver and Registry
Normative Reference: CROA Framework v1.0.1 §4.2 Context Resolver / §4.5 Grounding

Maintains registered targets and maps actions to expected target types.
Fails closed with TARGET_NOT_REGISTERED or TARGET_TYPE_MISMATCH.
Zero domain-specific pricing or external pilot fixtures in generic baseline.
"""


class ContextRegistry:
    def __init__(self):
        self._registry: dict[str, str] = {}
        self._action_target_types: dict[str, str] = {}
        self._init_defaults()

    def _init_defaults(self):
        self._registry = {
            "customer:871": "customer",
            "service:billing": "service",
            "service:notifications": "service",
            "environment:dev": "environment",
            "environment:prod": "environment",
            "endpoint:analytics.internal": "endpoint",
            "resource:default": "resource",
        }
        self._action_target_types = {
            "get_customer": "customer",
            "export_customers": "endpoint",
            "change_config": "environment",
            "deploy_service": "service",
            "delete_environment": "environment",
            "get_resource": "resource",
            "export_records": "endpoint",
            "delete_resource": "resource",
        }

    @property
    def registry(self) -> dict[str, str]:
        return self._registry

    @property
    def action_target_types(self) -> dict[str, str]:
        return self._action_target_types

    def register_target(self, target: str, target_type: str) -> None:
        """Registers a target identifier and its semantic target type."""
        self._registry[target] = target_type

    def unregister_target(self, target: str) -> None:
        """Removes a target identifier from the registry."""
        self._registry.pop(target, None)

    def register_action_target_type(self, action: str, target_type: str) -> None:
        """Registers the required target type for an action."""
        self._action_target_types[action] = target_type

    def clear(self) -> None:
        """Clears all registered targets and action target types."""
        self._registry.clear()
        self._action_target_types.clear()

    def reset_to_defaults(self) -> None:
        """Resets the registry to baseline generic entries."""
        self._init_defaults()

    def resolve_target(self, action: str, target: str) -> tuple[bool, str]:
        """
        Grounds target identifier against registered context.
        Fails closed if target is unknown or does not match action's expected type.
        """
        if target not in self._registry:
            return False, "TARGET_NOT_REGISTERED"

        expected_type = self._action_target_types.get(action)
        actual_type = self._registry[target]

        if expected_type and actual_type != expected_type:
            return False, "TARGET_TYPE_MISMATCH"

        return True, "GROUNDED"


# Global default context registry instance
default_context_registry = ContextRegistry()

# Exposed compatibility dictionary aliases
FEDERATED_CONTEXT_REGISTRY = default_context_registry.registry
ACTION_TARGET_TYPES = default_context_registry.action_target_types


def register_target(target: str, target_type: str) -> None:
    default_context_registry.register_target(target, target_type)


def register_action_target_type(action: str, target_type: str) -> None:
    default_context_registry.register_action_target_type(action, target_type)


def resolve_target(action: str, target: str) -> tuple[bool, str]:
    return default_context_registry.resolve_target(action, target)
