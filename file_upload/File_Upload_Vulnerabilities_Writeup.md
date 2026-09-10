# File Upload Vulnerabilities — Lab Writeup & Methodology Guide

This document consolidates your File Upload Vulnerabilities lab notes into a structured writeup: what each lab demonstrates, the underlying vulnerability class, and the real-world fixes a development team would apply.

## 2.0 Core concept

Unrestricted or improperly restricted file upload is one of the most direct paths to Remote Code Execution (RCE): if an attacker can (a) get arbitrary content onto the server's filesystem and (b) get that content *executed* by the web server, the game is over. Every lab you did attacks one half of that equation:

| Lab | Which half is bypassed |
|---|---|
| Basic web shell upload | No restriction at all — both halves trivially satisfied |
| Content-Type restriction bypass | The *check* (client-supplied `Content-Type` header) is trusted instead of actual content |
| Path traversal | The *storage location* restriction — write outside the intended, non-executable folder |
| Extension blacklist bypass (`.htaccess`) | The *execution mapping* itself is attacker-redefined |
| Polyglot upload | The *content inspection* (image signature check) is fooled by a dual-purpose file |
| Race condition | The *order of operations* — file is executable before validation completes |

## 2.1 Remote code execution via web shell upload (no filtering)

**What happened:** Uploaded `exploit.php` containing `<?php echo file_get_contents('/home/carlos/secret'); ?>` directly as an avatar with zero server-side restriction; the file landed at a predictable `/files/avatars/exploit.php` and executed on request.

**Concept:** Baseline case — no validation of extension, MIME type, or content at all. Demonstrates why "an image upload field" is inherently dangerous once you allow arbitrary filenames/extensions to be stored inside the webroot.

**Fix:** Enforce a strict allow-list of extensions AND verify actual file content (see 2.5), store outside the webroot or in a location with script execution disabled.

## 2.2 Web shell upload via Content-Type restriction bypass

**What happened:** Server rejected `Content-Type: application/x-php` but accepted the exact same PHP payload once the multipart `Content-Type` header was changed to `image/png`.

**Concept:** The `Content-Type` header in a multipart upload is **entirely client-controlled** — it is metadata the browser sends, not a property the server has independently verified. Trusting it as a security control is equivalent to trusting a self-reported ID card.

**Fix:** Never rely on the `Content-Type` header (or the filename extension) for security decisions. Validate actual file content server-side — e.g., verify magic bytes/file signature (JPEG starts with `FF D8 FF`, PNG with `89 50 4E 47...`), and better yet, re-encode/re-render uploaded images through a trusted image-processing library (which will simply fail or strip anything that isn't genuinely a valid image, including embedded PHP — this also defeats 2.5's polyglot trick).

## 2.3 Web shell upload via path traversal

**What happened:** The `filename` field in the multipart body was set to `..%2fexploit.php` (URL-encoded `../`), letting the file land one directory above the intended `avatars/` folder — the destination directory had different execution rules than the sandboxed avatar folder.

**Concept:** If the server builds the destination path via naive string concatenation (`$target_dir . $_FILES['avatar']['name']`) without sanitizing the filename, path traversal sequences in the filename let you choose the destination directory, potentially escaping any per-directory restrictions (e.g., a `.htaccess` that disables script execution *only* inside `avatars/`).

**Fix:** Never derive the storage path from user-supplied filenames. Generate the filename/path server-side (e.g., a random UUID + a hardcoded, allow-listed extension) and strip/reject any path separators or traversal sequences (`../`, `..\\`, encoded variants) defensively even though you shouldn't be trusting user input for the path at all.

## 2.4 Web shell upload via extension blacklist bypass (Apache `.htaccess`)

**What happened:** The app blacklisted `.php` but didn't block `.htaccess` uploads. Uploading a `.htaccess` file containing `AddType application/x-httpd-php .l33t` reconfigured Apache (for that directory) to execute any `.l33t` file as PHP. A second upload, `exploit.l33t` (an extension not on the blacklist), then executed as PHP.

**Concept:** Blacklists are fundamentally fragile — they enumerate what you thought of, not everything possible. Apache's per-directory `.htaccess` override mechanism is itself an "upload" vector: if you can write a file whose *name* the blacklist doesn't cover, you can redefine what "executable" means in that directory.

**Fix:**
- Use an **allow-list** of extensions (e.g., only `.jpg`, `.jpeg`, `.png`, `.gif`), rejecting everything else — including config files like `.htaccess`, `web.config`, `.user.ini`.
- Set `AllowOverride None` on upload directories in the Apache vhost config so `.htaccess` files placed there have no effect at all — this single server config fix eliminates the entire technique.
- Serve uploaded content from a separate domain/subdomain or object storage (S3, GCS) with no script execution capability whatsoever, decoupling "can be uploaded" from "can be executed" completely.

## 2.5 Remote code execution via polyglot web shell upload

**What happened:** The app validated actual image content (not just extension/MIME type), but `exiftool` was used to embed a PHP payload inside a genuine JPEG's `Comment` EXIF metadata field, then the file was saved with a `.php` extension. Because the file's magic bytes/structure still passed as a valid JPEG, content-based validation passed — but Apache/PHP still executed it as PHP because of its `.php` extension.

**Concept — Polyglot files:** A single file that is simultaneously valid as two different formats (here, a valid JPEG *and* a file whose extension triggers PHP interpretation). Content-signature validation alone is insufficient if the *execution decision* is still made purely from the file extension — you've fixed "is this really an image?" but not "will the server ever try to execute this file?"

**Fix (this is the most important lab conceptually):**
- **Re-encode/re-render uploaded images** through a trusted library (e.g., resize and re-save with PHP's GD/Imagick, Pillow in Python) rather than merely validating and storing the original bytes. Re-encoding regenerates the file from decoded pixel data, discarding EXIF/metadata blocks entirely, so embedded payloads cannot survive.
- Combine content validation *with* strict extension allow-listing *and* execution-disabled storage — no single layer alone is sufficient (defense in depth). This lab exists specifically to show that "check the file is really an image" is necessary but not sufficient.
- Strip all metadata (EXIF, XMP, comments) as a matter of course for any uploaded image, independent of any specific attack you're defending against.

## 2.6 Web shell upload via race condition (TOCTOU)

**What happened (from the vulnerable code you extracted):**
```php
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file); // file written FIRST
if (checkViruses($target_file) && checkFileType($target_file)) { // validated AFTER
    echo "uploaded";
} else {
    unlink($target_file); // deleted only if invalid
}
```
The file is moved into the public, web-accessible directory *before* it's validated, and only removed afterward if it fails. This creates a window — between `move_uploaded_file()` and `unlink()` — during which a malicious file sits in a publicly reachable path and can be requested/executed, even though it will shortly be deleted.

**Concept — Time-Of-Check to Time-Of-Use (TOCTOU) race condition:** Any pattern where a resource is made available/usable before its validity has been confirmed, and only cleaned up afterward, creates a race window. An attacker fires the upload request and, in parallel (often via repeated rapid requests using something like Burp's "Turbo Intruder" to win the race reliably), requests the file during that window — one successful hit is enough to get the payload to execute (e.g., writing a webshell to a persistent location or exfiltrating data) before the app deletes it.

**Fix:**
1. **Validate before making public**, not after: write the upload to a temporary, non-web-accessible location, run all checks there, and only move it into the public directory once it has passed *every* check. This eliminates the race window entirely (check-then-move, not move-then-check).
2. If atomicity is hard to guarantee, use a random/unpredictable temporary filename during the validation window so an attacker can't guess the URL to request during the race, as a defense-in-depth backstop (not a substitute for #1).
3. Ensure the upload directory itself has script execution disabled (ties back to 2.4) — even a successful race against a webshell payload is neutralized if PHP execution isn't possible there in the first place.

## 2.7 General file-upload security checklist (defense in depth, layered)
1. **Validate content**, not filename/extension/MIME type (magic bytes, and ideally full re-encode for images).
2. **Allow-list** extensions explicitly; never rely on a blacklist.
3. **Rename** files server-side (random name, fixed safe extension) — never trust the client-supplied filename for storage.
4. **Store outside the webroot**, or in a directory/bucket with script execution explicitly disabled (`AllowOverride None`, no PHP handler mapping, S3/GCS with no execute capability).
5. **Serve from a separate origin** (different domain/subdomain, or a CDN) so even a successfully uploaded malicious file can't execute in the main application's security context, and to avoid same-origin issues (stored XSS via uploaded HTML/SVG).
6. **Check-then-move, never move-then-check** — eliminate TOCTOU windows.
7. **Limit file size** and scan for malware with tooling that's actually invoked synchronously and correctly (not bypassable via the same race-condition pattern).
8. **Set correct response headers** on download (`Content-Disposition: attachment`, restrictive `Content-Type`, `X-Content-Type-Options: nosniff`) so even a stored non-executable malicious file (e.g., an HTML file) can't be rendered/executed by a victim's browser.

---

---

# Takeaway

Every lab's fix comes down to the same discipline: never let client-supplied input decide security-relevant behavior on the server — not the filename, not the extension, not the declared MIME type, and not the order of validation-versus-execution. Content must be verified server-side, storage/execution must be decoupled from anything the client controls, and validation must always happen before a file becomes reachable, never after.
