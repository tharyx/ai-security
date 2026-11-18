"""Hand-built malicious-STYLE pickle byte strings for the scanner tests.

!!! These bytes are only ever SCANNED. No test, demo or loader in this repo unpickles them. !!!

They show the shapes real malicious model files take. The "command" is `echo CANARY`,
so even an accident would be harmless. The pickle that tests actually LOAD (to prove the
risk is real) is built from harmless_payload.py and only writes a canary file.

Opcode cheat sheet:  c = GLOBAL, \\x93 = STACK_GLOBAL, R = REDUCE (call), . = STOP,
\\x8c = SHORT_BINUNICODE (push string), \\x94 = MEMOIZE, h = BINGET, 0 = POP, \\x85 = TUPLE1
"""

import pickle

MALICIOUS_STYLE = {
    # Protocol 0, the classic textbook form: GLOBAL 'os system', then REDUCE.
    "global_os_system": b"cos\nsystem\n(S'echo CANARY'\ntR.",
    # Protocol 4: module and name are pushed as strings, then STACK_GLOBAL combines them.
    "stack_global_os_system": (
        b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93\x8c\x0becho CANARY\x94\x85R."
    ),
    # Evasion: 'os' is stored in the memo, a decoy string is pushed, then 'os' is fetched
    # back with BINGET. A scanner that only reads string literals sees 'harmless.system'.
    "memo_trick_os_system": (
        b"\x80\x04\x8c\x02os\x940\x8c\x08harmless\x940h\x00\x8c\x06system\x94\x93"
        b"\x8c\x0becho CANARY\x94\x85R."
    ),
    # Evasion: payload first, then a broken stream. pickle.load() would already have run the
    # payload before it hits the broken byte, but some scanners gave up on a parse error.
    "broken_stream_after_payload": b"cos\nsystem\n(S'echo CANARY'\ntR" + b"\xff\xff",
    # Evasion: a harmless pickle, and a second pickle appended after its STOP opcode.
    "second_pickle_appended": pickle.dumps({"weights": [0.1, 0.2]}) + b"cos\nsystem\n(S'echo CANARY'\ntR.",
    # Not on any denylist, but timeit.timeit() executes a string of Python code.
    # A denylist misses it; an allowlist does not.
    "gadget_not_on_denylist": b"\x80\x04\x8c\x06timeit\x94\x8c\x06timeit\x94\x93\x8c\x04pass\x94\x85R.",
}
