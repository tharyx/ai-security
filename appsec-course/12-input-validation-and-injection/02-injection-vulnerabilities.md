# Lesson 02: Injection Vulnerabilities

**Syllabus items covered:** [CASP 5] "Injection Vulnerabilities", "Cross-Site Scripting (XSS)", "SQL Injection", "ORM Injection", "NoSQL Injection", "Server Side Request Forgery", "Deserialization Issues", "Mass Assignment Issues", "Prepared Statements", "Exploiting Mass Assignment Vulnerabilities", "Insecure Deserialization To Remote Code Execution", "Preventing Insecure Deserialization In Java", "Automated SQL Injection Using SQLMAP".

**Time:** 2 hours. **Labs:** [injection-playground](labs/injection-playground/README.md), [mass-assignment](labs/mass-assignment/README.md), [insecure-deserialization](labs/insecure-deserialization/README.md), [mini-sqlmap](labs/mini-sqlmap/README.md). Web-app basics of SQLi, XSS, SSRF and command injection are in [chapter 01](../01-security-champions-and-appsec-basics/README.md); this lesson is the API-focused, deeper version.

> Only test systems you own or have written permission to test.

## 1. Injection vulnerabilities

**Injection = untrusted data is interpreted as code or commands by some interpreter.** The interpreter can be a SQL engine, an ORM, a NoSQL query engine, an OS shell, an LDAP server, an XML parser, a template engine, a browser (XSS), a log parser (Log4Shell) or an LLM (prompt injection, see the repo's [LLM security module](../../02-llm-security/)).

The universal fix: **keep data and code in separate channels** (bind variables, argument arrays, safe APIs), plus validation and least privilege. OWASP Top 10 lists Injection as **A03:2021** and **A05:2025**; the OWASP API Top 10 2019 had **API8 Injection**, which the 2023 list folded into other items ([chapter 13](../13-owasp-api-top-10-and-other-threats/README.md)).

## 2. Cross-Site Scripting (XSS)

The browser is the interpreter: attacker data becomes HTML/JavaScript in another user's page.

| Type | Where the payload lives | API angle |
|---|---|---|
| Reflected | In the request, echoed in the response | API error messages that echo input with `Content-Type: text/html` |
| Stored | Saved in the database, shown later | API stores a comment; the web or admin UI renders it raw |
| DOM-based | Client-side JS writes data to a sink (`innerHTML`, `eval`) | SPA renders API JSON with `innerHTML` |

APIs cause XSS when they return the **wrong content type** (`text/html` for JSON), echo input in errors, or store data that a front end later renders unsafely. Defences: `Content-Type: application/json` + `X-Content-Type-Options: nosniff`, **context-aware output encoding** in the front end, **CSP** and **Trusted Types** ([lesson 04](04-output-encoding-csp-and-trusted-types.md)). XSS used for privilege escalation is a lab in [chapter 13](../13-owasp-api-top-10-and-other-threats/labs/xss-privilege-escalation/README.md).

## 3. SQL injection

```python
# vulnerable                                           # fixed: bind variable
sql = f"SELECT * FROM products WHERE name LIKE '%{t}%'"  cur.execute("... WHERE name LIKE ?", (f"%{t}%",))
```

Techniques: tautology (`' OR 1=1 --`), **UNION** to read other tables, error-based, **boolean-blind**, **time-based blind**, stacked queries (where supported), out-of-band (DNS). In APIs, SQLi hides in JSON fields, sort/filter parameters, headers (`X-Forwarded-For` logged into SQL) and GraphQL arguments.

**DBA view:** you know why bind variables matter for **performance** (shared cursors, no hard parse). They matter even more for **security**: the bind value is never parsed as SQL. Also: least privilege for the application schema user (no DBA role, no `CREATE ANY`, no access to `DBA_USERS`), and no dynamic SQL with `EXECUTE IMMEDIATE` on concatenated input in PL/SQL (use `USING` binds and `DBMS_ASSERT` for identifiers).

## 4. ORM injection

ORMs (Hibernate, SQLAlchemy, Django ORM, Sequelize, Entity Framework) parameterize by default, but every ORM has a **raw escape hatch**: `raw()`, `extra()`, `text()`, HQL/JPQL string building, `literal()`, `FromSqlRaw`. Injection also hides in **identifiers** that cannot be bound: `ORDER BY`, column names, table names. The lab's `order_by` takes user text and turns the sort order into a yes/no oracle that leaks the admin password.

Fix: never pass user text into raw fragments; **allowlist** identifiers (sortable columns) and map user choices to them.

## 5. NoSQL injection

Document databases accept **query objects**. If the API passes JSON from the client straight into a query, the client can send **operators**:

```json
{"username": "admin", "password": {"$ne": ""}}
```

`$ne` (not equal), `$gt`, `$regex` (enumerate values letter by letter) and server-side JavaScript (`$where`, now discouraged/removed in newer MongoDB versions; verify) turn a login into a bypass. Fix: **type checks** (a password must be a string), reject keys starting with `$`, schema validation, and driver options that disable server-side JS.

## 6. Server Side Request Forgery

The API fetches a URL that the client supplies (link previews, webhooks, PDF/image fetchers, import-from-URL, XML external entities) and an attacker points it at **internal** targets: cloud metadata (`169.254.169.254`), admin panels, `localhost` services, internal APIs. OWASP API7:2023 is SSRF.

Bypass tricks the lab covers: decimal/octal/IPv6 IP forms, DNS names that resolve to internal IPs, redirects from an allowed host to an internal one. Defences:

- **Allowlist** destinations (hosts, schemes, ports) when the feature allows it.
- **Resolve, then check the IP** (block private, loopback, link-local, reserved ranges), then **connect to that IP** (avoid DNS rebinding).
- **Do not follow redirects** (or re-check every hop).
- **Network egress controls** from the fetching service; cloud **IMDSv2** (token required) or blocking metadata from app pods.
- Return generic errors (no response body, no timing differences) to avoid blind SSRF port scanning.

## 7. Deserialization issues

Native object deserialization (Java `ObjectInputStream`, .NET `BinaryFormatter`, Python `pickle`, PHP `unserialize`, Ruby `Marshal`, YAML loaders with object tags) rebuilds **objects of types named in the data** and calls their methods. With attacker-controlled bytes, a chain of existing library classes (**gadget chain**) leads to remote code execution. Famous examples: the Apache Commons Collections gadget chains published in 2015, which affected Jenkins, WebLogic, JBoss and WebSphere, and many later WebLogic deserialization CVEs.

**Insecure deserialization to RCE** is shown safely in the lab: a pickle payload whose `__reduce__` calls a harmless canary function. The point is identical: the attacker chose the function.

### Preventing insecure deserialization in Java

1. **Do not deserialize untrusted data with native serialization.** Use JSON/protobuf with a schema, mapped to plain DTOs (and disable polymorphic typing in Jackson: avoid `enableDefaultTyping`/`@JsonTypeInfo(use = CLASS)` on untrusted input).
2. If you cannot avoid it, use **`ObjectInputFilter`** (JEP 290, Java 9 and backported to 8u121+; JEP 415 in Java 17 adds a JVM-wide filter factory) to **allowlist** classes and cap depth, array sizes and references:

```java
// Not compiled here: illustrative snippet (verify against your JDK version).
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=5;maxrefs=500;maxbytes=65536;maxarray=1000;" +
    "com.example.dto.Session;com.example.dto.Prefs;java.lang.String;!*");
try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
    in.setObjectInputFilter(filter);          // per-stream filter
    Session s = (Session) in.readObject();    // anything not allowlisted -> InvalidClassException
}
// JVM-wide alternative: -Djdk.serialFilter="com.example.dto.*;java.lang.String;!*"
```

3. Keep libraries patched (gadget classes get hardened), run with least privilege, and monitor for `InvalidClassException` spikes.
4. Sign serialized data (HMAC) for integrity, but treat that as defence in depth.

## 8. Mass assignment issues

The API binds request JSON to an internal model, so clients can set fields they should not (`is_admin`, `role`, `balance`, `owner_id`, `email_verified`). **Exploiting mass assignment vulnerabilities**: read GET responses, docs and JS to learn field names, then add them to PUT/PATCH/POST bodies and check whether they persisted. Fix: per-operation input DTOs with allowlisted fields, reject unknown fields, separate output schemas. In OWASP API 2023 this is part of **API3 BOPLA**.

**Scenario.** In 2012 a GitHub user exploited a Rails mass-assignment flaw to add his SSH key to the Rails organisation's repository and pushed a commit to prove it. Rails then made strong parameters (allowlisting) the default.

## 9. Prepared statements

A prepared statement sends the **SQL text** and the **values** separately. The database parses and plans the SQL once with placeholders (`?`, `:name`, `$1`), then binds values as data. No value can change the statement's structure.

| Language | Safe pattern |
|---|---|
| Python DB-API | `cur.execute("SELECT ... WHERE id = %s", (id,))` (placeholder style depends on driver) |
| Java JDBC | `PreparedStatement ps = c.prepareStatement("... WHERE id = ?"); ps.setLong(1, id);` |
| .NET | `cmd.Parameters.AddWithValue("@id", id)` (or typed `Add`) |
| Node (pg) | `client.query("... WHERE id = $1", [id])` |
| PL/SQL | `EXECUTE IMMEDIATE '... WHERE id = :1' USING v_id;` |

Limits: identifiers (table/column names, `ORDER BY` direction) cannot be bound; use allowlists or `DBMS_ASSERT.SIMPLE_SQL_NAME`. Stored procedures are safe only if they do not build dynamic SQL from their arguments.

## 10. Automated SQL injection with sqlmap

**sqlmap** (open source, actively maintained) automates detection and exploitation: techniques **B**oolean-blind, **E**rror-based, **U**nion, **S**tacked, **T**ime-based and inline **Q**ueries; DBMS fingerprinting; enumeration (`--dbs`, `--tables`, `--dump`); tamper scripts to evade simple filters. It takes a URL or a saved Burp request (`-r`). The [mini-sqlmap lab](labs/mini-sqlmap/README.md) rebuilds the B and T techniques and binary-search extraction in 80 lines, and [real-tools/sqlmap.md](real-tools/sqlmap.md) has hedged commands. Use it only against the course lab.

## Check yourself

1. Why can't `ORDER BY` columns be passed as bind variables, and what do you do instead?
2. What two checks does a robust SSRF defence make after resolving the hostname?
3. What does Java's `ObjectInputFilter` allowlist, and where can you set it?
