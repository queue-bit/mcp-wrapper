# Requirements: none (stdlib only)
from __future__ import annotations

import ast
import math
import operator

DESCRIPTION = (
    "Evaluate a mathematical expression and return the result. "
    "Supports arithmetic operators (+, -, *, /, //, %, **) and common math functions: "
    "sqrt, sin, cos, tan, asin, acos, atan, atan2, sinh, cosh, tanh, "
    "log, log10, log2, exp, abs, round, floor, ceil, factorial, gcd, "
    "degrees, radians, hypot, min, max, sum. "
    "Constants: pi, e, tau, inf."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["expression"],
    "properties": {
        "expression": {
            "type": "string",
            "description": (
                "Mathematical expression to evaluate. "
                "Examples: 'sqrt(2) * pi', '(3 + 4) ** 2', 'log(100, 10)', 'sin(radians(45))'"
            ),
        },
    },
}

# ---------------------------------------------------------------------------
# Safe AST evaluator — no eval(), only whitelisted operations
# ---------------------------------------------------------------------------

_NAMES: dict[str, float] = {
    "pi": math.pi,
    "e": math.e,
    "tau": math.tau,
    "inf": math.inf,
}

_FUNCTIONS: dict[str, object] = {
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "asin": math.asin,
    "acos": math.acos,
    "atan": math.atan,
    "atan2": math.atan2,
    "sinh": math.sinh,
    "cosh": math.cosh,
    "tanh": math.tanh,
    "log": math.log,
    "log10": math.log10,
    "log2": math.log2,
    "exp": math.exp,
    "abs": abs,
    "round": round,
    "floor": math.floor,
    "ceil": math.ceil,
    "factorial": math.factorial,
    "gcd": math.gcd,
    "degrees": math.degrees,
    "radians": math.radians,
    "hypot": math.hypot,
    "min": min,
    "max": max,
    "sum": sum,
}

_BINOPS: dict[type, object] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_UNOPS: dict[type, object] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _eval(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _eval(node.body)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value  # preserve int vs float so factorial(10) works
        raise ValueError(f"Unsupported literal type: {type(node.value).__name__}")

    if isinstance(node, ast.Name):
        if node.id in _NAMES:
            return _NAMES[node.id]  # type: ignore[return-value]
        raise ValueError(f"Unknown name {node.id!r} — did you mean a function call?")

    if isinstance(node, ast.BinOp):
        op = _BINOPS.get(type(node.op))
        if op is None:
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        return op(_eval(node.left), _eval(node.right))  # type: ignore[operator]

    if isinstance(node, ast.UnaryOp):
        op = _UNOPS.get(type(node.op))
        if op is None:
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        return op(_eval(node.operand))  # type: ignore[operator]

    if isinstance(node, ast.List):
        return [_eval(el) for el in node.elts]  # type: ignore[return-value]

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Only direct function calls are supported (e.g. sqrt(2), not obj.method())")
        fn = _FUNCTIONS.get(node.func.id)
        if fn is None:
            raise ValueError(f"Unknown function {node.func.id!r}")
        if node.keywords:
            raise ValueError("Keyword arguments are not supported")
        args = [_eval(arg) for arg in node.args]
        return fn(*args)  # type: ignore[operator]

    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


def _safe_eval(expression: str) -> int | float:
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Syntax error in expression: {exc}") from exc
    return _eval(tree)


# ---------------------------------------------------------------------------

async def execute(arguments: dict) -> str:
    expression = arguments["expression"]
    result = _safe_eval(expression)
    # Return a clean integer representation when the result is a whole number
    if isinstance(result, float) and result.is_integer() and abs(result) < 1e15:
        return f"{expression} = {int(result)}"
    return f"{expression} = {result}"
