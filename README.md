# AI-PHP-JS-Fuzzer v5 
_Auto‑crawler & exploit‑launcher for modern web stacks (Angular / React / Vue, classic PHP, REST/GraphQL, Web‑Sockets)._

---

## What’s Inside

- **Dynamic SPA Crawler**  
  Executes JavaScript, waits for `networkidle`, harvests:
  - `<a>`, `href`, `routerLink`, hash‑routes  
  - All HTML **forms** (GET & POST)  
  - **XHR / fetch / GraphQL** requests  
  - **Web‑Socket** handshake URLs  
  - Hidden iframes & Shadow‑DOM sources  

- **Auto‑Form Fuzzer**  
  ➜ Mutates every discovered field with AI‑style obfuscated payloads (`whoami`, `<svg…>`, `gopher://…`) and submits via the form’s real method.

- **Server‑Side Attack Arsenal**
  - Multi‑stage **param recursion** (`?x=http://…?y=whoami`)
  - Protocol/scheme abuse – `gopher://`, `file://`, `data://`, `blob:`  
  - Split‑eval chains `";alert` + `('XSS')`  
  - **MIME‑type confusion** / JSON → HTML  
  - Legacy‑Unicode / double‑encode path bypass  
  - **CRLF smuggling** & **chunk‑desync** probes

- **Client‑Side / DOM Exploits**
  - Clipboard hijack input (`oncopy=fetch(...)`)  
  - **Prototype‑pollution** (`__proto__`) detection  
  - **Web‑Socket echo XSS** (sends `<svg/onload>` via WS)  
  - Async/await race → `eval(alert)` runtime exec  
  - Iframe sandbox clone / Shadow‑DOM injection  

- **Playwright Helper (Hardened)**
  - Headless Chromium with `--disable-web-security`, TLS ignore  
  - Timeout + _one retry_ – returns `None` so scan never aborts  
  - Shared instance for DOM modules (performance)

- **Zero‑Crash Logging**
  - UTF‑8 safe console + `super_fuzz.log`  
  - Any exception = logged & skipped, not program exit

---

- **Feature Checklist**
 - PHP / HTML / JS / API endpoint discovery
 - Automatic form enumeration & fuzzing
 - Obfuscated RCE & XSS payload mutation
 - Client‑side & server‑side vulnerability triggers
 - Hidden DOM route detection (SPA)
 - Stream‑wrapper, gopher/file/data probing
 - CRLF & HTTP request‑smuggling probes
 - Robust timeout / error handling
 - Cross‑platform UTF‑8 logging
 - more...

 ##  Quick Run

```bash
pip install playwright requests
playwright install chromium
python super_fuzz.py           # enter target URL when prompted
