"""Admin operations (fixture, parsed only)."""
from auth import require_role


@require_role("admin")
def delete_user(uid):
    return uid


def delete_order(oid):  # expect: authz
    return oid


def purge_cache():  # expect: authz
    return None


def _delete_tmp():
    return None


def delete_cache_entry(key):  # nosec E904 - internal job, not reachable from HTTP
    return key
