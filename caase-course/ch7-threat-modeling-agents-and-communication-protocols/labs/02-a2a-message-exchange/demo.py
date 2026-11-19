"""Demo: client agent discovers the summarizer's card over 127.0.0.1 HTTP, sends a task, reads the artifact."""
import json

from aisec_lab import load_lab_module

a2a = load_lab_module(__file__, "a2a_lite")

agent = a2a.make_summarizer()
srv, url = a2a.serve(agent)
try:
    client = a2a.A2AClient(url)
    card = client.discover()
    print("Agent Card:", json.dumps({k: card[k] for k in ("name", "url", "securitySchemes")}))
    print("Skills:", [s["id"] for s in card["skills"]])
    task = client.send("summarize", "Agents talk over A2A. This second sentence is dropped.")
    print("Task", task["id"], "status log:", task["statusLog"])
    print("Artifact:", task["artifacts"][0]["parts"][0]["text"])
    need = client.send("summarize", "")
    print("Empty input ->", need["status"]["state"])
    done = client.send("summarize", "Thanks. Done.", task_id=need["id"])
    print("Follow-up ->", done["status"]["state"], done["statusLog"])
finally:
    srv.shutdown()
