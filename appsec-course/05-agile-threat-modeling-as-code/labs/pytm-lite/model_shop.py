"""Threat model WITH code: the shop system described as Python objects (pytm style).

``build(secure=False)`` returns the first-draft design. ``build(secure=True)`` returns the same
system after the team added the controls the findings asked for.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pytmlite import TM, Actor, Boundary, Data, Dataflow, Datastore, Server  # noqa: E402


def build(secure: bool = False) -> TM:
    with TM("Shop", "Customers browse and order; the API stores orders and customer profiles.") as tm:
        internet = Boundary("Internet", trusted=False)
        dmz = Boundary("DMZ")
        internal = Boundary("Internal")

        creds = Data("login credentials", classification="SECRET", isCredentials=True)
        profile = Data("customer profile", classification="RESTRICTED", isPII=True)
        order = Data("order", classification="RESTRICTED")

        user = Actor("Customer", inBoundary=internet)
        web = Server("Web App", inBoundary=dmz, rendersHTML=True,
                     authenticatesSource=secure, hasAccessControl=secure, sanitizesInput=secure,
                     encodesOutput=secure, handlesResourceConsumption=secure, logsSecurityEvents=secure)
        api = Server("Orders API", inBoundary=internal,
                     authenticatesSource=True, hasAccessControl=secure, sanitizesInput=True,
                     handlesResourceConsumption=True, logsSecurityEvents=secure)
        db = Datastore("Orders DB", inBoundary=internal, storesPII=True,
                       isEncrypted=secure, hasAccessControl=True, isBackedUp=secure)

        Dataflow(user, web, "Login and browse", protocol="HTTPS" if secure else "HTTP",
                 isEncrypted=secure, data=(creds, profile))
        Dataflow(web, api, "Place order", protocol="HTTPS", isEncrypted=True, data=(order, profile))
        Dataflow(api, db, "SQL query", protocol="TLS", isEncrypted=True, data=(order, profile))
        Dataflow(db, api, "Result rows", protocol="TLS", isEncrypted=True, data=(order,))
        Dataflow(web, user, "HTML page", protocol="HTTPS" if secure else "HTTP", isEncrypted=secure,
                 data=(profile,))
    return tm


if __name__ == "__main__":
    # pytm-style command line: python model_shop.py --dfd | --seq | --report <template> [--secure]
    tm = build(secure="--secure" in sys.argv)
    if "--dfd" in sys.argv:
        print(tm.dfd())
    elif "--seq" in sys.argv:
        print(tm.seq())
    elif "--report" in sys.argv:
        tpl = Path(sys.argv[sys.argv.index("--report") + 1]).read_text(encoding="utf-8")
        print(tm.report(tpl))
    else:
        for f in tm.process():
            print(f"{f.severity:6} {f.sid:6} {f.target:12} {f.stride}")
