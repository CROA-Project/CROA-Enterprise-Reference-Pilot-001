"""
CROA Reference Harness — Generic Parameter Constraint Engine
Normative Reference: CROA Framework v1.0.1 §4.5.1 / §4.9.1

Evaluates declarative parameter constraints against request parameters.
Operates with strict fail-closed semantics across all operator checks.
Zero business-domain names embedded in control flow.
"""

from typing import Any

SUPPORTED_OPERATORS: set[str] = {"equals", "not_equals", "max", "min", "in", "not_in", "type", "required"}

SUPPORTED_TYPE_NAMES: set[str] = {"int", "float", "number", "str", "bool", "list", "dict"}


def evaluate_parameter_constraints(constraints: dict[str, Any] | None, parameters: dict[str, Any] | None) -> tuple[bool, str]:
    """
    Evaluates declarative parameter constraints against incoming parameters.
    Returns (True, "VALID") or (False, "<REASON_CODE>: detail").
    Fails closed on any malformed rule, unknown operator, type mismatch, or violated rule.
    """
    if not constraints:
        return True, "VALID"

    if not isinstance(constraints, dict):
        return False, "MALFORMED_CONSTRAINTS: Parameter constraints specification must be a dictionary"

    params = parameters or {}
    if not isinstance(params, dict):
        return False, "MALFORMED_PARAMETERS: Parameters payload must be a dictionary"

    for param_name, rule_spec in constraints.items():
        if not isinstance(rule_spec, dict):
            return False, f"MALFORMED_RULE: Rule specification for parameter '{param_name}' must be a dictionary of operator rules"

        # Check for unknown operators first (Fail-Closed)
        unknown_ops = set(rule_spec.keys()) - SUPPORTED_OPERATORS
        if unknown_ops:
            return False, f"UNKNOWN_OPERATOR: Operator(s) {sorted(list(unknown_ops))} not supported for parameter '{param_name}'"

        # Evaluate 'required' operator
        is_required = rule_spec.get("required")
        if is_required is not None:
            if not isinstance(is_required, bool):
                return False, f"MALFORMED_RULE: Operator 'required' on parameter '{param_name}' must be boolean"
            if is_required and param_name not in params:
                return False, f"REQUIRED_PARAMETER_MISSING: Parameter '{param_name}' is required by authorization constraint"

        # If parameter is not present and not required, skip remaining value assertions
        if param_name not in params:
            continue

        val = params[param_name]

        # Evaluate 'type' operator
        if "type" in rule_spec:
            expected_type = rule_spec["type"]
            if expected_type not in SUPPORTED_TYPE_NAMES:
                return False, f"UNSUPPORTED_TYPE_SPECIFICATION: Type '{expected_type}' is not recognized"

            type_valid = False
            if expected_type == "int":
                type_valid = isinstance(val, int) and not isinstance(val, bool)
            elif expected_type == "float":
                type_valid = isinstance(val, float)
            elif expected_type == "number":
                type_valid = isinstance(val, (int, float)) and not isinstance(val, bool)
            elif expected_type == "str":
                type_valid = isinstance(val, str)
            elif expected_type == "bool":
                type_valid = isinstance(val, bool)
            elif expected_type == "list":
                type_valid = isinstance(val, list)
            elif expected_type == "dict":
                type_valid = isinstance(val, dict)

            if not type_valid:
                return False, f"TYPE_MISMATCH: Parameter '{param_name}' expected type '{expected_type}', got '{type(val).__name__}'"

        # Evaluate 'equals' operator
        if "equals" in rule_spec:
            expected_val = rule_spec["equals"]
            if val != expected_val:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value '{val}' does not equal required '{expected_val}'"

        # Evaluate 'not_equals' operator
        if "not_equals" in rule_spec:
            disallowed_val = rule_spec["not_equals"]
            if val == disallowed_val:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value '{val}' equals disallowed '{disallowed_val}'"

        # Evaluate 'max' operator
        if "max" in rule_spec:
            max_bound = rule_spec["max"]
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                return False, f"COMPARISON_ERROR: Candidate value '{val}' for parameter '{param_name}' is not numeric"
            if not isinstance(max_bound, (int, float)) or isinstance(max_bound, bool):
                return False, f"COMPARISON_ERROR: Upper bound '{max_bound}' for parameter '{param_name}' is not numeric"
            if val > max_bound:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value {val} exceeds upper bound {max_bound}"

        # Evaluate 'min' operator
        if "min" in rule_spec:
            min_bound = rule_spec["min"]
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                return False, f"COMPARISON_ERROR: Candidate value '{val}' for parameter '{param_name}' is not numeric"
            if not isinstance(min_bound, (int, float)) or isinstance(min_bound, bool):
                return False, f"COMPARISON_ERROR: Lower bound '{min_bound}' for parameter '{param_name}' is not numeric"
            if val < min_bound:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value {val} is below lower bound {min_bound}"

        # Evaluate 'in' operator
        if "in" in rule_spec:
            allowed_set = rule_spec["in"]
            if not isinstance(allowed_set, (list, set, tuple)):
                return False, f"MALFORMED_RULE: Operator 'in' on parameter '{param_name}' must specify a list or set"
            if val not in allowed_set:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value '{val}' is not in allowed set {allowed_set}"

        # Evaluate 'not_in' operator
        if "not_in" in rule_spec:
            disallowed_set = rule_spec["not_in"]
            if not isinstance(disallowed_set, (list, set, tuple)):
                return False, f"MALFORMED_RULE: Operator 'not_in' on parameter '{param_name}' must specify a list or set"
            if val in disallowed_set:
                return False, f"CONSTRAINT_VIOLATION: Parameter '{param_name}' value '{val}' is in disallowed set {disallowed_set}"

    return True, "VALID"
