"""Small business tools. DELIBERATELY VULNERABLE: no input validation, so bad types crash."""


def apply_discount(price, percent):
    return price - price * percent / 100


def split_bill(total, people):
    return total / people
