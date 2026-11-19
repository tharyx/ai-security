"""Small business tools with explicit validation."""

from .errors import ToolInputError


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        raise ToolInputError(f"{name} must be a number")
    return value


def apply_discount(price, percent):
    price, percent = _number(price, "price"), _number(percent, "percent")
    if price < 0 or not 0 <= percent <= 100:
        raise ToolInputError("price or percent out of range")
    return price - price * percent / 100


def split_bill(total, people):
    total = _number(total, "total")
    if isinstance(people, bool) or not isinstance(people, int) or people < 1:
        raise ToolInputError("people must be a positive integer")
    return total / people
