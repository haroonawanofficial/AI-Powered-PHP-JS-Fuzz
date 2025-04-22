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

- **Auto‑Hook**  
  ➜ This will help you to mutate as if your browsing the webpage, bypassing completely any waf on the spot, they blocks user agents, etc

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
```

 ##  Compare it with all Kali XSS/PHP/JS Tools

| Feature / Tool                    | AI_PHP_JS_Fuzzer v5.5                                                                                                                                     | XSStrike                                                   | DalFox                                                          | XSSer                                          |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------------------------|------------------------------------------------|
| **Language**                      | Python + Playwright                                                                                                                                    | Python                                                     | Go (single binary)                                             | Python                                         |
| **Crawling (dynamic)**            | Full SPA crawler via Playwright: executes React/Vue/SPA JS, discovers `<routerLink>`, XHR endpoints, Shadow DOM, etc.                                   | Optional headless crawl via Puppeteer (`--headless`) but basic link extraction otherwise | Built‑in headless crawler (`--crawl` + `--script`) that uses a bundled Chromium driver | Limited: simple link discovery from HTML; no real JS execution |
| **Form Discovery & Fuzzing**      | Parses every `<form>` (GET/POST), auto‑fuzzes all inputs with AI‑mutated payloads                                                                        | Can fuzz parameters but must be told which; basic form submission | Detects forms automatically when crawling; fuzzes common names   | Auto‑discovers forms but no deep SPA/form‑wait support |
| **JS‑based / DOM XSS**            | Exercises ShadowDOM, MutationObserver, clipboard hijack, WebSocket injections, prototype pollution, iframe clones, etc.                                  | Tests reflected XSS via script injection; limited DOM‑only tests | Includes some DOM XSS payloads, but no scripted observers or WS   | Focuses on reflected/stored XSS; minimal DOM support |
| **Headless Browser**              | Playwright (Chromium) full control, auto‑hook into real Chrome profile, screenshots, form‑wait                                                           | Puppeteer under the hood (optional)                         | Headless Chromium embedded; auto‑hook via script flag            | No headless browser; pure HTTP                 |
| **HTTP/2 & HTTP/3 Smuggle**       | CRLF, chunk‑desync, HTTP2 smuggle, QUIC header fuzz, protocol‑scheme abuse                                                                               | None                                                       | None                                                           | None                                           |
| **Multi‑layer Payload Mutator**   | AI‑style mutator: reverse, quote, scramble, chain, header/body smuggle                                                                                  | Basic SQL/XSS payloads; no “AI” variants                     | Standard payload library; no randomization                       | Standard payload library                       |
| **Out‑of‑band (OOB) / SSRF**      | Hidden OOB via `gopher://`, SSRF fuzz, YAML injection, OGNL injection                                                                                   | No SSRF, minimal OOB                                        | Some SSRF via URL param fuzz                                    | No SSRF or OOB                                 |
| **Proxy / DNS Control**           | `--no-proxy-server`, `--proxy-bypass-list=*`, direct DNS, environment‑proxy toggle                                                                      | Can respect `HTTP_PROXY`; no built‑in override flags        | Honors env proxy; no override flags                             | Honors env proxy                                |
| **Extensibility**                 | Fully scripted—easy to add new modules or payload types                                                                                                 | Open‑source, but you’d need to edit the Python script       | Go code; you’d have to recompile to extend                      | Python script; extensible but less modular      |
| **Ease of Use**                   | One big monolithic script—with many flags (`--autohook`, `--debug`, etc.)                                                                               | Simple CLI: `xsstrike -u URL [--crawl] [--headless]`         | Simple CLI: `dalfox url URL [--crawl] [--script]`              | Simple CLI: `xsser -u URL [options]`            |
| **Installation**                  | `pip install playwright bs4` + `playwright install --with-deps`                                                                                        | `pip install xsstrike` + `npm install -g puppeteer`         | `go install github.com/hahwul/dalfox/v2@latest`                | `pip install XSSer`                            |
| **Legal / Risk Considerations**   | Very aggressive: multi‑protocol, smuggling—use only on authorized targets                                                                               | Primarily safe reflected XSS testing                        | Safe reflected XSS with headless support                        | Basic reflected/stored XSS; low‑risk            |
