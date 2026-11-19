import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

tinyapp = load_lab_module(__file__, "tinyapp")
agent_mod = load_lab_module(__file__, "agent")
qa = load_lab_module(__file__, "qa_suite")


def show(title, suite):
    app = tinyapp.App()
    with agent_mod.IastAgent(mode="report") as agent:
        qa.run_suite(app, agent, suite)
    print(f"== {title}: {len(suite)} functional tests, {agent.sink_calls} sink calls, {len(agent.report())} vulnerable flow(s) ==")
    for f in agent.report():
        print(f"[{f.kind}] during {f.endpoint}  (sink value, no attack payload in the test data: {f.sink_value!r})")
        for line in f.trace:
            print("    " + line)


show("current nightly suite", qa.CURRENT_SUITE)
print()
show("suite + test_read_doc", qa.FULL_SUITE)

print("\n== known gap: f-string drops the taint ==")
app = tinyapp.App()
with agent_mod.IastAgent() as agent:
    with agent.request("fstring_handler"):
        app.user_by_name_fstring(tinyapp.Request({"name": "alice"}))
print("flows reported:", len(agent.report()), "(the SQL is built unsafely, but the toy agent cannot see it)")
