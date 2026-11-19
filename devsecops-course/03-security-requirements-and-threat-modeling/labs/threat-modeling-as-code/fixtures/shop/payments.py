"""Payment service (fixture)."""

# @exposes Internal:PaymentService to Tampering with a client-supplied order total
# @mitigates Internal:PaymentService against Tampering with the total is recomputed from catalog prices
# @exposes Internal:PaymentService to Repudiation with no record of who approved a refund
# @connects Internal:PaymentService to Internal:Database with TLS
def charge(order):
    return True


# @exposes Internal:PaymentService to Information Disclosure with card numbers in debug logs
def debug_dump(order):
    return str(order)
