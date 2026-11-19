from a2a_messages import InsecureBus, Rejected, SecureBus, Worker, make_message, sign

NOW = 1000.0
keys = {"planner": b"FAKE-planner-key", "attacker": b"FAKE-attacker-key"}
spoofed = make_message("planner", "worker", "t1", "task.update", {"dest": "acct-EVIL"}, NOW)

w = Worker()
InsecureBus(w).deliver(spoofed)
print("INSECURE bus: task state ->", w.tasks)

w = Worker()
bus = SecureBus(w, keys, {"t1": {"planner"}})
tests = {
    "unsigned spoof": spoofed,
    "forged signature": sign(keys["attacker"], spoofed),
}
good = sign(keys["planner"], make_message("planner", "worker", "t1", "task.update", {"dest": "acct-A"}, NOW))
for name, msg in tests.items():
    try:
        bus.deliver(msg, NOW)
    except Rejected as e:
        print(f"SECURE bus: {name:<18} rejected: {e}")
bus.deliver(good, NOW)
print("SECURE bus: legit message accepted ->", w.tasks)
try:
    bus.deliver(good, NOW + 2)
except Rejected as e:
    print("SECURE bus: replay             rejected:", e)
