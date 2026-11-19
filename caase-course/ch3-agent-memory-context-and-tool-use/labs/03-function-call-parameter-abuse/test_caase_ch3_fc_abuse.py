"""Function-calling parameter abuse (SQL, path, authorization, extra parameters) and its fixes."""

import pytest

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "fc_abuse")
TRAVERSAL = "../secrets.txt"


@pytest.fixture
def make():
    keep = []

    def _make(**flags):
        host, tmp = f.make_host(**flags)
        keep.append(tmp)
        return host

    yield _make
    for t in keep:
        t.cleanup()


def test_normal_use(make):
    h = make()
    assert "book" in h.say("orders for 1") and f.CANARY_NOTE not in h.say("orders for 1")
    assert "Q1 report" in h.say("report q1.txt")


def test_sql_injection_through_the_parameter_dumps_other_customers(make):
    h = make()
    assert f.CANARY_NOTE in h.say("orders for 1 OR 1=1")


def test_authorization_bypass_by_changing_the_id(make):
    h = make()
    assert "laptop" in h.say("orders for 2")  # Alice reads Bob's orders (BOLA)


def test_path_traversal_through_the_parameter(make):
    h = make()
    assert f.CANARY_FILE in h.say(f"report {TRAVERSAL}")


def test_schema_validation_alone_blocks_injection_and_traversal(make):
    h = make(schema_check=True)
    assert h.say("orders for 1 OR 1=1") == "error: customer_id has invalid format"
    assert h.say(f"report {TRAVERSAL}") == "error: name not in enum"


def test_schema_alone_does_not_stop_a_valid_but_foreign_id(make):
    h = make(schema_check=True)
    assert "laptop" in h.say("orders for 2")  # valid format, wrong owner: needs session binding


def test_bound_parameters_alone_stop_sql_injection_but_not_traversal(make):
    h = make(bound_params=True)
    assert f.CANARY_NOTE not in h.say("orders for 1 OR 1=1")
    assert f.CANARY_FILE in h.say(f"report {TRAVERSAL}")


def test_session_binding_ignores_the_argument(make):
    h = make(session_binding=True)
    assert "laptop" not in h.say("orders for 2")


def test_confinement_alone_stops_traversal(make):
    h = make(confine_paths=True)
    assert h.say(f"report {TRAVERSAL}") == "error: path outside reports"


def test_extra_and_mistyped_parameters_are_rejected(make):
    h = make(schema_check=True)
    assert "unexpected parameter" in h.say('call get_orders {"customer_id": "1", "debug": "true"}')
    assert "must be a string" in h.say('call get_orders {"customer_id": ["1"]}')
    assert "missing customer_id" in h.say('call get_orders {}')


def test_all_layers_keep_normal_use_working_and_log_calls(make):
    h = make(**f.DEFENDED)
    assert "book" in h.say("orders for 1")
    assert "Q2 report" in h.say("report q2.txt")
    assert f.CANARY_NOTE not in h.say("orders for 1 OR 1=1") and f.CANARY_FILE not in h.say(f"report {TRAVERSAL}")
    assert len(h.audit) == 4


def test_validator_subset():
    assert f.validate({"customer_id": "12"}, f.SCHEMAS["get_orders"]) == ""
    assert f.validate("x", f.SCHEMAS["get_orders"]) == "arguments must be an object"
