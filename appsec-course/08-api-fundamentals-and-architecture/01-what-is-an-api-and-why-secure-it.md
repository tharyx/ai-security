# Lesson 01: What Is an API, and Why Secure It?

**Syllabus items covered:** "Introduction to Application Programming Interface", "What is an API?", "Need for an API", "Why Should You Secure Your APIs?", "APIs vs. Web Applications" ([CASP 1]).

**Time:** 45 minutes. **Safety:** concepts only. Only test systems you own or have written permission to test.

> **DBA analogy.** You never let application users log in to Oracle with SQL*Plus and type their own `UPDATE`. You give them a **package** (`ORDERS_API.create_order(...)`) with a fixed signature, grants on the package only, and validation inside it. A web API is the same idea over HTTP: a fixed, documented contract in front of data and logic.

## 1. Introduction to application programming interfaces

An **application programming interface (API)** is a contract that lets one piece of software ask another piece of software to do something, without knowing how it is built inside. The contract says:

- **what** you can ask for (operations, or endpoints),
- **how** to ask (the protocol and the data format),
- **who** may ask (authentication and authorization),
- **what comes back** (responses and errors).

APIs exist at every level: an operating-system API (`open()`, `read()`), a library API (Python's `sqlite3`), a database API (OCI, JDBC) and, the subject of this course, **web APIs**: programs talking over HTTP(S), usually exchanging JSON.

## 2. What is an API?

In this course "API" means a **web API**: a server that accepts HTTP requests at URLs such as `https://shop.example/api/v1/orders/42` and returns machine-readable data.

| Part | Example | Meaning |
|---|---|---|
| Endpoint | `/api/v1/orders/{id}` | a resource or operation |
| Verb (method) | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | what to do with it |
| Request body | `{"item": 7, "qty": 2}` | input data |
| Response | `201 Created` + JSON | result and status |
| Credentials | `Authorization: Bearer <token>` | who is calling |

The caller is usually **another program**: a mobile app, a single-page web app (React, Angular), a partner's server, a script, or an AI agent using tools.

## 3. Need for an API

Why organisations build APIs:

1. **One back end, many front ends.** The same order API serves the website, the Android app, the iOS app and the call-centre tool.
2. **Integration.** Payments (Stripe, Razorpay), maps, SMS, identity providers and partners connect by API.
3. **Microservices.** Large systems are split into services that talk to each other by API (chapter [lesson 03](03-api-architecture-protocols-and-deployment.md)).
4. **Automation.** Cloud platforms (AWS, Azure, GCP), CI/CD and infrastructure-as-code are all driven through APIs.
5. **Products.** Some companies *sell* API access (data feeds, LLM APIs).

## 4. Why should you secure your APIs?

- **APIs expose data and logic directly.** There is no screen hiding fields: whatever the API returns, the attacker sees, even if the app does not display it.
- **They are easy to automate against.** An attacker can call `GET /orders/1` ... `/orders/100000` in minutes. Rate and object-level checks matter more than in a click-driven UI.
- **They are many and they change fast.** Old versions (`/v1`), forgotten test endpoints and undocumented partner APIs are attack surface that nobody monitors (see [chapter 09 recon](../09-api-tooling-and-reconnaissance/README.md)).
- **Real breaches are API breaches.** Many large public incidents of recent years were an API that returned another customer's record (broken object level authorization) or an unauthenticated endpoint. The **OWASP API Security Top 10 (2023 edition is current; verify at owasp.org)** exists because these bugs differ from classic web bugs. Chapter 13 covers it in full.
- **Compliance.** Personal and payment data passing through APIs falls under GDPR, India's DPDP Act, PCI DSS and similar rules.

## 5. APIs vs. web applications

| | Traditional web application | API |
|---|---|---|
| Client | a human with a browser | a program (app, script, partner, agent) |
| Output | HTML pages for display | data (JSON, XML, protobuf) |
| State | often server-side sessions with cookies | often stateless tokens on every call |
| Where logic lives | much of it on the server, rendered into pages | split: client renders, API enforces |
| Typical bugs | XSS, CSRF, clickjacking | BOLA/IDOR, broken auth, excessive data exposure, mass assignment, no rate limits |
| Discovery | crawl links | read specs, JS bundles, guess paths |
| Testing | crawler + scanner | spec-driven requests, auth-aware, per-object tests |

**Key point for interviews:** a modern "web app" is usually a JavaScript front end **plus** an API. The browser-side controls (hidden buttons, disabled fields, client-side validation) do not protect anything: the API must enforce every rule itself.

## 6. Scenario: the hidden field that was not hidden

A food-delivery app shows each user only their own past orders. The mobile app calls `GET /api/v2/orders?user_id=1093`. A curious user changes `1093` to `1094` in an intercepting proxy and receives another person's address and phone number. The UI never displayed other users' data, so the team thought it was "protected". The API trusted a client-supplied identifier.

**Fix:** derive the user from the authenticated token on the server (`WHERE owner_id = :token_user_id`, like a VPD policy), ignore `user_id` from the client, and add a test that user A cannot read user B's order. You will build exactly this kind of test in [chapter 11](../11-api-authorization-and-oauth/README.md).

## 7. Self-check

1. Give three reasons a company builds an API rather than only a website.
2. Why is client-side validation never a security control for an API?
3. Name two bug classes far more common in APIs than in classic server-rendered pages.

Next: [Lesson 02, HTTP for APIs](02-http-protocol-for-apis.md).
