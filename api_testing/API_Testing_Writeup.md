# API Testing — Lab Writeup & Methodology Guide

This document consolidates  API Testing lab notes into a structured writeup: what each lab demonstrates, the underlying vulnerability class, the general methodology  used (so it transfers to labs/targets you haven't seen), and the real-world fixes a development team would apply.

## 1.0 Core concepts

APIs expand the attack surface beyond what's visible in the browser UI. Three ideas underpin almost every API vulnerability class worked through:

- **Hidden functionality ≠ secure functionality.** An endpoint or parameter that isn't rendered in the UI is still reachable if the backend accepts it. "Security by obscurity" fails the moment someone enumerates it.
- **Trust boundary confusion.** Backends often trust the client to only send "allowed" fields/verbs, but frameworks that auto-bind JSON/form data to internal objects don't know which fields *should* be user-controllable.
- **Verbose errors are a map.** 400/404/500 error messages frequently leak internal routing, parameter names, or even raw upstream API definitions — exactly what is exploited in nearly every lab below.

**Methodology skeleton** (applies to all 5 labs):
1. Map normal traffic (Burp Proxy history) and diff request vs. response JSON structures.
2. Deliberately break things — drop parameters, drop the whole path, send invalid values — and read the *exact wording* of errors.
3. Use out-of-band characters (`%23` for `#`, `%26` for `&`, `?`, `../`) to see if your input lands unescaped inside a server-side path or query string.
4. Once you find a hidden parameter/field, brute-force or enumerate its name (Intruder + wordlists like Burp's "server-side variable names").
5. Cross-reference client-side JS (`.js` files served to the browser) — they often reference the *real* backend parameter names even when the HTML form doesn't.

---

## 1.1 Exploiting an API endpoint using documentation

**What happened:** `PATCH /api/user/wiener` updates email and leaks data in the response. Stripping the identifier from the path (`PATCH /api`) surfaced the API's own OpenAPI/Swagger documentation, which revealed an undocumented (from the client's perspective) `DELETE /api/user/{username}` operation — enough to delete the `carlos` account.

**Concept:** Exposed API documentation (Swagger/OpenAPI, GraphQL introspection, etc.) is a gift to an attacker — it's a complete map of every endpoint, parameter, and HTTP verb the backend supports, including ones the frontend never calls.

**Real-world workarounds/remediation:**
- Never serve `/api`, `/swagger.json`, `/openapi.json`, `/v1/api-docs` etc. on production without authentication — gate documentation endpoints behind auth or strip them from prod builds entirely.
- Apply the principle of least privilege per-operation: just because an endpoint *exists* in the spec doesn't mean every authenticated user should be able to call it. Enforce authorization at the operation level, not just "logged in or not."
- Rate-limit and log requests to `/api` root and malformed-identifier requests — probing for docs is a detectable pattern.

---

## 1.2 Exploiting server-side parameter pollution (SSPP) in a query string

**What happened:** The `/forgot-password` endpoint takes `username` and, server-side, builds a query string to call an internal API (`GET /internal/api?username=...&field=email`). By URL-encoding `&` (`%26`) and `#` (`%23`) inside the `username` value, you injected an extra parameter (`field`) and truncated the rest of the server-side query — eventually discovering `field=reset_token` leaked the admin's password reset token directly in the JSON response.

**Concept — Server-Side Parameter Pollution:** The client's single input parameter is concatenated, unescaped, into a query string that's sent to an *internal* API. Because the outer app doesn't URL-encode/escape before forwarding, you can smuggle additional key=value pairs or truncate the query using `#`.

**Methodology used:**
1. Confirm baseline behavior (resend original request in Repeater).
2. Break the username into an invalid one → note the exact error.
3. Inject `%26x=y` → "Parameter is not supported" confirms `&` is being interpreted server-side.
4. Inject `%23` (truncate) → "Field not specified" confirms a `field` parameter exists downstream that you're currently blanking out.
5. Brute-force `field` name via Intruder + built-in "server-side variable names" list → `email` and `username` both return 200.
6. Read the associated `forgotPassword.js` for the *real* endpoint parameter name (`reset_token` / `passwordResetToken`) instead of guessing blindly.
7. Set `field=reset_token`, harvest the leaked token, use it at `/forgot-password?reset_token=...` to complete an account takeover.

**Real-world workarounds/remediation:**
- Never build a downstream request (URL, SQL, shell command, etc.) via string concatenation of user input. Use parameterized/structured calls (e.g., pass `field` as a fixed, hardcoded value server-side, not derived from client input at all).
- If a value truly must flow through, URL-encode it *again* before appending to the internal query string, so `#`/`&` in the value can't break out of its parameter.
- Apply an allow-list of legitimate `field` values server-side rather than trusting whatever the internal API accepts.
- Don't return sensitive tokens (password reset tokens, session identifiers) in any JSON response body under any code path — deliver them out-of-band (e.g., via email) only.

---

## 1.3 Finding and exploiting an unused/shadow API endpoint

**What happened:** `/api/products/1/price` was never referenced by the visible UI, but wasn't disabled server-side. `OPTIONS` revealed it accepted `GET, PATCH`; iterative fuzzing of `Content-Type` and body (`{}` → `'price' parameter missing`) revealed exactly what body shape it expected. Submitting `{"price": 0}` let you buy an item for free.

**Concept — Shadow/undocumented endpoints:** Endpoints that exist for internal tooling, admin panels, or deprecated features but were never removed or properly access-controlled. `OPTIONS` (and systematic HTTP verb tampering — trying `GET`, `POST`, `PUT`, `PATCH`, `DELETE` against every discovered path) is a fast way to discover what a given path *actually* supports versus what the UI exposes.

**Real-world workarounds/remediation:**
- Maintain an authoritative API inventory / gateway config; anything not explicitly documented and access-controlled should 404, not silently accept requests.
- Disable `OPTIONS` verbose `Allow:` headers in production, or at minimum don't let it reveal state-changing verbs (`PATCH`, `DELETE`) without matching authorization checks.
- Server-side price/business-logic values must never be accepted from the client — compute/validate price server-side from the product ID, ignore any client-supplied price field entirely.
- Regularly audit and retire dead endpoints (dependency/route scanning in CI).

---

## 1.4 Exploiting a mass assignment vulnerability

**What happened:** `GET /api/checkout` returned a `chosen_discount: {percentage: 0}` object that the `POST /api/checkout` request never included. Adding that object back into the POST body and setting `percentage: 100` got a 100%-off order.

**Concept — Mass assignment (a.k.a. autobinding):** Frameworks like Spring, Rails, Django REST Framework, and many Node.js ORMs let you bind an entire incoming JSON body directly onto an internal model/object for convenience. If the developer doesn't explicitly define which fields are writable (a Data Transfer Object / allow-list of bindable fields), *every* field on the model — including `isAdmin`, `role`, `price`, `chosen_discount` — becomes attacker-controllable.

**How to spot it (identifying hidden parameters):**
- Diff a `GET` of the same resource against the `POST`/`PATCH` body — any field present in the GET response but absent from the writable request is a mass-assignment candidate.
- Send the suspected field back with a deliberately invalid type/value (e.g., `"isAdmin": "foo"`). If the app throws a *type validation* error rather than *"unrecognized field"*, that proves the field is bound internally — it's just waiting for a valid value.

**Real-world workarounds/remediation:**
- Use explicit allow-lists (DTOs / serializers) for every writable endpoint — never bind request JSON directly onto a persistence-layer model.
- Framework-specific mitigations: Rails `strong_parameters`, Spring `@JsonIgnore`/dedicated request DTOs, Django REST Framework explicit `fields` on serializers, .NET `[Bind(Include=...)]`.
- Treat privilege/pricing/role fields as server-derived only — never accept them from client input regardless of allow-list convenience.
- Contract/schema validation (JSON Schema, OpenAPI request validation middleware) that rejects unexpected properties (`additionalProperties: false`).

---

## 1.5 Exploiting server-side parameter pollution in a REST URL (path-based SSPP)

**What happened:** Same root cause as 1.2, but the `username` value is placed into the *path segment* of a server-side REST call rather than a query string. Using `administrator#` and `administrator?` confirmed path-placement (truncation via `#`/`?`); `../administrator` vs `./administrator` confirmed you could traverse the path; walking `../../../../` far enough exposed the API root, where `openapi.json` was fetched directly to reveal the real internal route template: `/api/internal/v1/users/{username}/field/{field}`. From there you injected `/field/passwordResetToken` and even downgraded the API version (`../../v1/...`) to reach a version that still exposed the token.

**Concept:** Identical vulnerability class to 1.2 (SSPP) but manifesting in path-based routing instead of query strings — and it additionally demonstrates **API version downgrade** as an exploitation technique: newer API versions patch a leak, but if the client can select/traverse to an older version, the vulnerability persists.

**Real-world workarounds/remediation:**
- All of the SSPP fixes from 1.2 apply (never concatenate raw input into a server-side path).
- Retire and fully decommission old API versions rather than leaving them reachable — a "deprecated" endpoint that's just hidden is still exploitable.
- Canonicalize and validate paths server-side before use (reject `../`, `%2e%2e`, encoded traversal sequences) at the point where user input is about to be used to construct *any* downstream request — not just for file paths.
- Don't expose OpenAPI/Swagger definitions at guessable, unauthenticated paths (ties back to 1.1).

## 1.6 General API testing checklist (beyond these 5 labs)
- Enumerate every HTTP verb per discovered path (`OPTIONS`, verb tampering).
- Diff GET vs. POST/PATCH/PUT JSON shapes for every resource (mass assignment hunting).
- Fuzz `Content-Type` and `Accept` headers — some backends behave differently or leak stack traces for unsupported types.
- Try both API versioning schemes if present (`/v1/`, `/v2/`, header-based `Accept: application/vnd.api+json;version=1`) — older versions are frequently less hardened.
- Look for BOLA/IDOR (Broken Object Level Authorization) by swapping IDs you don't own into otherwise-valid requests — not covered directly in your labs but the #1 item on the OWASP API Security Top 10 and a natural next step from mass assignment.
- Automate the "break it and read the error" loop with Burp Intruder + a parameter-name wordlist rather than doing it by hand once you've confirmed the pattern.

---
