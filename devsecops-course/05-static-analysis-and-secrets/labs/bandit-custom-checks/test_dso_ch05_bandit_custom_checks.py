from pathlib import Path

from aisec_lab import load_lab_module

bl = load_lab_module(__file__, "bandit_lite")
cc = load_lab_module(__file__, "corp_checks")
ev = load_lab_module(__file__, "evaluate")
APP = Path(__file__).resolve().parent / "fixtures" / "enterprise_app"
CUSTOM = bl.load_checks(cc)


def scan(src, plugins=None):
    return bl.scan_source(src, "t.py", plugins or CUSTOM)


def ids(issues):
    return [i.test_id for i in issues]


def test_plugin_discovery_finds_the_four_custom_checks():
    assert sorted(f._test_id for f in CUSTOM) == ["E901", "E902", "E903", "E904"]


def test_context_resolves_import_aliases():
    seen = []

    @bl.checks("Call")
    @bl.test_id("T1")
    def probe(ctx):
        seen.append(ctx.call_function_name_qual)

    scan("from corp_http import client as h\nimport os.path as p\nh.get('x')\np.join('a')\n", [probe])
    assert "corp_http.client.get" in seen and "os.path.join" in seen


def test_e901_flags_concat_fstring_format_but_not_constants_params_or_casts():
    bad = "import corpdb\ndef f(x):\n    return corpdb.execute('SELECT ' + x)\n"
    fstr = "import corpdb\ndef f(x):\n    return corpdb.execute(f'SELECT {x}')\n"
    fmt = "import corpdb\ndef f(x):\n    return corpdb.execute('SELECT {}'.format(x))\n"
    ok1 = "import corpdb\ndef f(x):\n    return corpdb.execute('SELECT * FROM t WHERE a = %s', (x,))\n"
    ok2 = "import corpdb\nT = 't'\ndef f():\n    return corpdb.execute('SELECT * FROM ' + T)\n"
    ok3 = "import corpdb\ndef f(x):\n    n = int(x)\n    q = 'SELECT %d' % n\n    return corpdb.execute(q)\n"
    assert ids(scan(bad)) == ["E901"] and ids(scan(fstr)) == ["E901"] and ids(scan(fmt)) == ["E901"]
    assert scan(ok1) == [] and scan(ok2) == [] and scan(ok3) == []


def test_e901_follows_a_local_variable():
    src = "import corpdb\ndef f(x):\n    q = 'SELECT ' + x\n    return corpdb.execute(q)\n"
    assert ids(scan(src)) == ["E901"]


def test_e902_timeout_rule_and_kwargs_exception():
    base = "from corp_http import client as http\n"
    assert ids(scan(base + "http.get('u')\n")) == ["E902"]
    assert scan(base + "http.get('u', timeout=2)\n") == []
    assert scan(base + "http.get('u', **opts)\n") == []


def test_e903_ignores_words_in_literals_harmless_names_and_masked_values():
    pre = "import logging\nlogger = logging.getLogger('x')\n"
    assert ids(scan(pre + "logger.info('reset', user.password)\n")) == ["E903"]
    assert ids(scan(pre + "logger.info('got %s', d['api_key'])\n")) == ["E903"]
    assert scan(pre + "logger.info('password reset requested')\n") == []
    assert scan(pre + "logger.info('n=%d', s.token_count)\n") == []
    assert scan(pre + "logger.info('k=%s', mask(u.api_key))\n") == []


def test_e904_requires_a_role_decorator_and_skips_private_helpers():
    assert ids(scan("def delete_x():\n    pass\n")) == ["E904"]
    assert scan("@require_role('admin')\ndef delete_x():\n    pass\n") == []
    assert scan("def _delete_x():\n    pass\n") == []


def test_nosec_with_and_without_ids():
    src = "def delete_x():  # nosec E904\n    pass\n"
    assert scan(src) == []
    assert ids(scan("def delete_x():  # nosec E901\n    pass\n")) == ["E904"]     # wrong id: still reported
    assert scan("def delete_x():  # nosec\n    pass\n") == []


def test_builtin_checks_find_the_legacy_issues():
    got = {i.test_id for i in bl.scan_path(APP / "legacy.py", bl.load_checks(bl))}
    assert {"B101", "B301", "B307", "B324", "B501", "B506", "B602"} <= got


def test_ground_truth_is_read_from_def_comments():
    truth = ev.ground_truth(APP)
    assert ("orders.py", "by_status", "sqli") in truth and ("admin.py", "purge_cache", "authz") in truth
    assert len(truth) == 8


def test_custom_checks_beat_the_generic_baseline_on_false_positives():
    base = ev.summarize(ev.score(APP, ev.baseline_issues(APP)))
    mine = ev.summarize(ev.score(APP, ev.custom_issues(APP)))
    assert base["fp"] == 5 and base["fn"] == 3
    assert mine == {"tp": 8, "fp": 0, "fn": 0}


def test_naive_b608_really_flags_constants_which_is_the_false_positive():
    sql = [i for i in ev.baseline_issues(APP) if i.test_id == "B608"]
    fns = {ev.function_at(APP, i.filename, i.lineno) for i in sql}
    assert {"count_all", "page"} <= fns
