from aisec_lab import load_lab_module

g = load_lab_module(__file__, "gql_extra")


def test_field_suggestions_leak_hidden_admin_field():
    err = g.Server(suggestions=True).execute(["adminExport"])["errors"][0]
    assert "Did you mean 'adminExportAllUsers'" in err


def test_schema_recovered_from_suggestions_without_introspection():
    found = g.recover_schema(g.Server(suggestions=True), g.WORDLIST)
    assert {"adminExportAllUsers", "internalPricingRules", "resetPassword"} <= found


def test_disabling_suggestions_stops_recovery_of_hidden_fields():
    found = g.recover_schema(g.Server(suggestions=False), g.WORDLIST)
    assert found == {"me"}


def test_array_batching_runs_hundreds_of_operations_in_one_request_without_limit():
    s = g.Server(False)
    s.execute_batch([["resetPassword"]] * 500)
    assert s.operations_executed == 500


def test_batch_limit_rejects_large_batches():
    s = g.Server(False, max_batch=10)
    assert "errors" in s.execute_batch([["me"]] * 11) and s.operations_executed == 0


def test_persisted_queries_reject_any_unregistered_query():
    s = g.Server(False, persisted_only=True)
    h = s.register(["me"])
    assert s.execute(query_hash=h) == {"data": {"me": "<me data>"}}
    assert "PersistedQueryNotFound" in s.execute(["adminExportAllUsers"])["errors"][0]
