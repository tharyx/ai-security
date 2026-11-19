"""A tiny inputSchema validator: required, types, no extra keys, string length cap."""

from .errors import ToolInputError

_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}
MAX_STRING = 256


def validate(arguments, schema: dict) -> None:
    if not isinstance(arguments, dict):
        raise ToolInputError("arguments must be an object")
    props = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in arguments:
            raise ToolInputError(f"missing argument: {name}")
    for name, value in arguments.items():
        if name not in props:
            raise ToolInputError(f"unexpected argument: {name}")
        kind = props[name]["type"]
        if isinstance(value, bool) and kind != "boolean":
            raise ToolInputError(f"wrong type for {name}")
        if not isinstance(value, _TYPES[kind]):
            raise ToolInputError(f"wrong type for {name}")
        if isinstance(value, str) and len(value) > MAX_STRING:
            raise ToolInputError(f"{name} is too long")
