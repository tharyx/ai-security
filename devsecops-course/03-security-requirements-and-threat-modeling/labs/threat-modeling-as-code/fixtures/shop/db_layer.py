"""Database access layer (fixture)."""

# @exposes Internal:Database to Tampering with SQL injection through string-built queries
# @mitigates Internal:Database against Tampering with parameterised queries only
# @exposes Internal:Database to Information Disclosure with verbose SQL errors returned to callers
# @mitigates Internal:Database against Information Disclosure with generic error pages and encrypted columns
# @mitigates Internal:Database against Elevation of Privilege with least-privilege DB account
def run_query(sql, params):
    return []
