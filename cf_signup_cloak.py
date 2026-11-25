#!/usr/bin/env python3
"""Register one Cloudflare account via CloakBrowser (anti-fingerprint Chromium).

Email:  <local>@<INBUCKET email domain>   -- catch-all Inbucket mailbox you run yourself
OTP:    polled from the Inbucket REST API, never through the registration proxy

Prerequisites:
  - a clean outbound proxy (socks5://host:port) configured via PROXY
  - an Inbucket instance receiving CF's verification mails for EMAIL_HOST
  - the cloakbrowser package (stealth-patched chromium launcher)
"""
from __future__ import annotations

import json
import os
import random
import re
import secrets
import string
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from urllib.request import ProxyHandler, Request, build_opener

os.environ.setdefault("TZ", "Asia/Shanghai")
try:
    time.tzset()  # type: ignore[attr-defined]
except Exception:
    pass

SIGNUP_URL = os.environ.get("CF_SIGNUP_URL", "https://dash.cloudflare.com/sign-up")
EMAIL_HOST = os.environ.get("CF_EMAIL_HOST", "").strip()  # e.g. inbox.example.com
INBUCKET_BASE = os.environ.get("INBUCKET_API_BASE", "").rstrip("/")  # Inbucket REST base, e.g. https://mail.example.com
INBUCKET_USER = os.environ.get("INBUCKET_USER", "inbucket")
INBUCKET_PASS = os.environ.get("INBUCKET_PASSWORD", "")  # must be set
CHROME = os.environ.get(
    "CLOAKBROWSER_BINARY_PATH",
    os.path.expanduser("~/.cloakbrowser/latest/chrome"),
)
PROXY = (os.environ.get("PROXY") or "").strip() or None
HEADLESS = os.environ.get("CLOAK_HEADLESS", "1").strip().lower() not in {"0", "false", "no", "off"}
OUT_PATH = Path(os.environ.get("CF_SIGNUP_OUT", "cf-signup-result.json"))
MODE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MODE", "register")).strip().lower()

LINK_RE = re.compile(
    r"https://(?:dash\.|www\.)?cloudflare\.com/[^\s\"'<>\\]+",
    re.I,
)


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def gen_email() -> str:
    fixed = (os.environ.get("CF_FIXED_EMAIL") or "").strip()
    if fixed:
        return fixed
    if not EMAIL_HOST:
        raise RuntimeError("CF_EMAIL_HOST not set")
    local = "cf" + time.strftime("%m%d%H%M") + secrets.token_hex(3)
    return f"{local}@{EMAIL_HOST}"


def gen_password() -> str:
    env = (os.environ.get("FIXED_PASSWORD") or "").strip()
    if env:
        return env
    alphabet = string.ascii_letters + string.digits
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(14))


def _auth_header() -> str:
    import base64

    raw = f"{INBUCKET_USER}:{INBUCKET_PASS}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _get_json(url: str) -> Any:
    for k in (
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
        "PROXY",
    ):
        os.environ.pop(k, None)
    req = Request(
        url,
        headers={
            "Authorization": _auth_header(),
            "Accept": "application/json",
            "User-Agent": "cf-signup-cloak",
        },
    )
    opener = build_opener(ProxyHandler({}))
    with opener.open(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore") or "null")


def dump_page(page, tag: str) -> dict[str, Any]:
    info = page.evaluate(
        """() => {
          const inputs = [...document.querySelectorAll('input,textarea,select,button')].slice(0, 40).map(e => ({
            tag: e.tagName, type: e.type || '', name: e.name || '', id: e.id || '',
            placeholder: e.placeholder || '', aria: e.getAttribute('aria-label') || '',
            text: (e.innerText || e.value || '').slice(0, 80),
          }));
          const ts = document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
          const iframes = [...document.querySelectorAll('iframe')].map(f => ({
            src: (f.src || '').slice(0, 200), id: f.id || '', title: f.title || '',
            w: f.offsetWidth, h: f.offsetHeight,
          }));
          const cap = document.querySelector('[class*="turnstile"], [class*="captcha"], [data-sitekey], #challenge-stage, [id*="cf-chl"]');
          return {
            url: location.href,
            title: document.title,
            body: (document.body && document.body.innerText || '').slice(0, 1200),
            inputs,
            turnstile_len: ts && ts.value ? ts.value.length : 0,
            has_turnstile_widget: !!(ts || iframes.length || document.querySelector('.cf-turnstile, [data-sitekey]')),
            iframe_src: (iframes[0] && iframes[0].src) || '',
            iframes,
            captcha_html: cap ? (cap.outerHTML || '').slice(0, 400) : '',
          };
        }"""
    )
    log(
        f"{tag} url={info.get('url')} title={info.get('title')!r} "
        f"ts_len={info.get('turnstile_len')} widget={info.get('has_turnstile_widget')} "
        f"inputs={len(info.get('inputs') or [])}"
    )
    for inp in (info.get("inputs") or [])[:18]:
        log(f"  el {inp}")
    body = (info.get("body") or "").replace("\n", " | ")
    log(f"  body={body[:400]}")
    return info


def click_human_widget(page) -> None:
    try:
        if os.environ.get("CF_SHOT", "1").strip() not in {"0", "false", "no"}:
            shot = "/tmp/cf-signup-widget.png"
            page.screenshot(path=shot, full_page=False)
            log(f"screenshot {shot}")
    except Exception as exc:
        log(f"screenshot: {exc}")
    try:
        loc = page.get_by_text("Verify you are human", exact=False)
        if loc.count() > 0:
            loc.first.scroll_into_view_if_needed(timeout=3000)
            box = loc.first.bounding_box()
            log(f"verify-human box={box}")
            if box:
                page.mouse.click(box["x"] - 24, box["y"] + box["height"] / 2)
                log("clicked left of 'Verify you are human'")
                page.wait_for_timeout(400)
            loc.first.click(timeout=2000)
            log("clicked 'Verify you are human' text")
            return
    except Exception as exc:
        log(f"verify-human click: {exc}")
    try:
        for f in page.frames:
            url = getattr(f, "url", "") or ""
            if "challenge" not in url and "turnstile" not in url:
                continue
            log(f"challenge frame {url[:120]}")
            try:
                t = f.get_by_text("Verify you are human", exact=False)
                if t.count() > 0:
                    box = t.first.bounding_box()
                    log(f"frame verify-human box={box}")
                    t.first.click(timeout=2000)
                    log("clicked verify-human inside frame")
                    if box:
                        page.mouse.click(box["x"] - 20, box["y"] + box["height"] / 2)
                    return
            except Exception as exc:
                log(f"frame verify-human: {exc}")
            try:
                el = f.frame_element()
                box = el.bounding_box()
                log(f"frame_element box={box}")
                if box:
                    page.mouse.click(box["x"] + 30, box["y"] + box["height"] / 2)
                    log("clicked frame_element left-center")
                    return
            except Exception as exc:
                log(f"frame_element: {exc}")
    except Exception as exc:
        log(f"frames: {exc}")
    try:
        loc = page.get_by_text("Let us know you are human", exact=False)
        if loc.count() > 0:
            loc.first.scroll_into_view_if_needed(timeout=3000)
            box = loc.first.bounding_box()
            if box:
                page.mouse.click(box["x"] + 20, box["y"] + 48)
                log(f"clicked below human heading {box}")
    except Exception as exc:
        log(f"coord click: {exc}")


def wait_turnstile(page, seconds: int = 40) -> int:
    token_len = 0
    steps = max(1, seconds // 2)
    for i in range(steps):
        if i in (0, 2, 5, 8) or (i >= 3 and i % 4 == 0):
            click_human_widget(page)
        token_len = int(
            page.evaluate(
                """() => {
                  const names = ['cf-turnstile-response', 'cf_challenge_response'];
                  for (const n of names) {
                    const el = document.querySelector(`input[name="${n}"], textarea[name="${n}"]`);
                    if (el && el.value) return el.value.length;
                  }
                  const byId = document.querySelector('[id*="cf-chl-widget"][id$="_response"]');
                  if (byId && byId.value) return String(byId.value).length;
                  if (window.turnstile && typeof turnstile.getResponse === 'function') {
                    try { return String(turnstile.getResponse() || '').length; } catch (e) {}
                  }
                  return 0;
                }"""
            )
            or 0
        )
        log(f"turnstile token_len={token_len} t+{i*2}s")
        if token_len > 50:
            return token_len
        page.wait_for_timeout(2000)
    return token_len


def type_into(page, selector: str, text: str, delay: int = 30) -> None:
    loc = page.locator(selector).first
    loc.wait_for(state="visible", timeout=20000)
    loc.click()
    page.wait_for_timeout(200)
    try:
        loc.fill("")
    except Exception:
        pass
    loc.type(text, delay=delay)


def poll_verify_mail(email: str, timeout: int = 180) -> dict[str, Any]:
    local = email.split("@", 1)[0]
    deadline = time.time() + timeout
    seen: set[str] = set()
    while time.time() < deadline:
        try:
            msgs = _get_json(f"{INBUCKET_BASE}/api/v1/mailbox/{local}")
        except Exception as exc:
            log(f"inbucket list err: {exc}")
            time.sleep(4)
            continue
        if not isinstance(msgs, list):
            time.sleep(3)
            continue
        log(f"inbucket mailbox={local} n={len(msgs)}")
        for m in msgs:
            mid = str(m.get("id") or "")
            if not mid or mid in seen:
                continue
            seen.add(mid)
            try:
                full = _get_json(f"{INBUCKET_BASE}/api/v1/mailbox/{local}/{mid}")
            except Exception as exc:
                log(f"inbucket read {mid} err: {exc}")
                continue
            body = full.get("body") or {}
            text = "\n".join(
                [
                    str(full.get("subject") or m.get("subject") or ""),
                    str(body.get("text") or ""),
                    str(body.get("html") or ""),
                ]
            )
            subj = str(full.get("subject") or m.get("subject") or "")
            frm = str(full.get("from") or m.get("from") or "")
            log(f"mail id={mid} from={frm} subject={subj!r}")
            links = [unquote(x.rstrip(").,;")) for x in LINK_RE.findall(text)]
            # prefer verify/confirm links
            ranked = sorted(
                dict.fromkeys(links),
                key=lambda u: (
                    0
                    if re.search(r"verif|confirm|token|email", u, re.I)
                    else 1
                ),
            )
            codes = re.findall(r"\b(\d{6})\b", text)
            if ranked or codes:
                return {
                    "id": mid,
                    "subject": subj,
                    "from": frm,
                    "links": ranked[:8],
                    "codes": codes[:4],
                    "snippet": text[:500],
                }
        time.sleep(4)
    return {}


def dash_fetch(page, path: str) -> Any:
    return page.evaluate(
        """async (path) => {
          const r = await fetch(path, {credentials: 'include', headers: {Accept: 'application/json'}});
          const t = await r.text();
          try { return {status: r.status, json: JSON.parse(t)}; }
          catch (e) { return {status: r.status, text: t.slice(0, 400)}; }
        }""",
        path,
    )


def save(result: dict[str, Any]) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    log(f"wrote {OUT_PATH}")


def launch_browser():
    os.environ["CLOAKBROWSER_BINARY_PATH"] = CHROME
    os.environ.setdefault("TZ", "Asia/Shanghai")
    from cloakbrowser import launch

    args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-webrtc",
    ]
    if HEADLESS:
        args.append("--headless=new")
    ext = []
    ext_dir = os.environ.get("TURNSTILE_PATCH", "")  # optional extra extension dir
    if ext_dir and Path(ext_dir).is_dir():
        ext.append(ext_dir)
        log(f"extension {ext_dir}")
    log(f"launch chrome={CHROME} headless={HEADLESS} proxy={PROXY or '(none)'} tz={os.environ.get('TZ')} ext={ext}")
    return launch(
        headless=HEADLESS,
        proxy=PROXY,
        args=args,
        stealth_args=True,
        timezone="Asia/Shanghai",
        locale="en-US",
        geoip=False,
        humanize=True,
        human_preset="careful",
        extension_paths=ext or None,
    )


def maybe_dismiss(page) -> None:
    for sel in (
        "#onetrust-reject-all-handler",
        "#onetrust-accept-btn-handler",
        'button:has-text("Reject")',
        'button:has-text("Accept All")',
        'button:has-text("I agree")',
    ):
        try:
            loc = page.locator(sel)
            if loc.count() > 0 and loc.first.is_visible():
                loc.first.click(timeout=2500)
                page.wait_for_timeout(400)
                log(f"clicked {sel}")
        except Exception:
            pass


def click_first(page, selectors: list[str], timeout: int = 8000) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel)
            if loc.count() > 0 and loc.first.is_visible():
                loc.first.click(timeout=timeout)
                log(f"clicked {sel}")
                return True
        except Exception as exc:
            log(f"click miss {sel}: {exc}")
    return False


def register() -> dict[str, Any]:
    email = gen_email()
    password = gen_password()
    result: dict[str, Any] = {
        "ok": False,
        "email": email,
        "password": password,
        "host": EMAIL_HOST,
        "proxy": PROXY,
        "chrome": CHROME,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    save(result)
    log(f"email={email}")

    browser = None
    context = None
    try:
        browser = launch_browser()
        ctx_kwargs: dict[str, Any] = {"viewport": {"width": 1280, "height": 1400}, "locale": "en-US"}
        if PROXY:
            ctx_kwargs["proxy"] = {"server": PROXY}
        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()

        create_error: list[str] = []

        def on_resp(resp) -> None:
            try:
                url = resp.url
                interesting = any(
                    x in url
                    for x in (
                        "api/v4",
                        "sign-up",
                        "turnstile",
                        "challenge",
                        "captcha",
                        "/user",
                        "verify",
                    )
                )
                if not interesting:
                    return
                log(f"HTTP {resp.status} {url[:180]}")
                if any(x in url for x in ("captcha", "/user", "sign-up", "membership", "accounts", "user/create")):
                    try:
                        txt = resp.text()
                        if txt:
                            log(f"  body={txt[:280]}")
                        if "user/create" in url or url.rstrip("/").endswith("/user"):
                            create_error.append(f"{resp.status} {txt[:240]}")
                    except Exception:
                        pass
            except Exception:
                pass

        page.on("response", on_resp)
        log(f"open {SIGNUP_URL}")
        last_err = None
        for attempt in range(3):
            try:
                page.goto(SIGNUP_URL, timeout=60000, wait_until="domcontentloaded")
                last_err = None
                break
            except Exception as exc:
                last_err = exc
                log(f"goto attempt {attempt+1}/3 failed: {exc}")
                page.wait_for_timeout(2000)
        if last_err is not None:
            raise last_err
        page.wait_for_timeout(6000)
        try:
            page.wait_for_load_state("networkidle", timeout=12000)
        except Exception:
            pass
        maybe_dismiss(page)
        info = dump_page(page, "after-goto")
        if MODE == "probe":
            result["ok"] = True
            result["probe"] = info
            result["mode"] = "probe"
            return result

        # some CF flows hide email until a button
        if not any((i.get("type") == "email" or i.get("name") == "email") for i in (info.get("inputs") or [])):
            click_first(
                page,
                [
                    'button:has-text("Sign up with email")',
                    'button:has-text("Create an account")',
                    'a:has-text("Sign up")',
                ],
            )
            page.wait_for_timeout(2000)
            info = dump_page(page, "after-signup-click")

        type_into(page, 'input[type=email], input[name=email], input[autocomplete="email"]', email)
        page.wait_for_timeout(400)
        # password may already be on the same form
        pw_sel = 'input[type=password], input[name=password], input[autocomplete="new-password"]'
        try:
            page.locator(pw_sel).first.wait_for(state="visible", timeout=8000)
            type_into(page, pw_sel, password, delay=25)
        except Exception:
            log("password not on first screen — submit email first")
            click_first(page, ['button[type=submit]', 'button:has-text("Continue")', 'button:has-text("Next")'])
            page.wait_for_timeout(3000)
            dump_page(page, "after-email-submit")
            type_into(page, pw_sel, password, delay=25)

        # optional name fields
        for sel, val in (
            ('input[name=first_name], input[autocomplete="given-name"]', random.choice(["James", "Ryan", "Emma", "Olivia"])),
            ('input[name=last_name], input[autocomplete="family-name"]', random.choice(["Smith", "Johnson", "Brown", "Lee"])),
        ):
            try:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    loc.first.click()
                    loc.first.type(val, delay=30)
            except Exception:
                pass

        maybe_dismiss(page)
        # terms checkbox
        try:
            boxes = page.locator("input[type=checkbox]")
            for i in range(min(boxes.count(), 3)):
                box = boxes.nth(i)
                if box.is_visible() and not box.is_checked():
                    box.check()
                    log(f"checked checkbox {i}")
        except Exception:
            pass

        dump_page(page, "pre-turnstile")
        try:
            page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
        except Exception:
            pass
        page.wait_for_timeout(800)
        ts_len = wait_turnstile(page, seconds=40)
        result["turnstile_len"] = ts_len
        dump_page(page, "post-turnstile")
        if ts_len <= 50:
            log("WARN turnstile input empty — CF signup may attach token on submit; clicking Sign up anyway")

        click_first(
            page,
            [
                'button[type=submit]:has-text("Sign up")',
                'button:has-text("Sign up")',
                'button:has-text("Create account")',
                'button:has-text("Create Account")',
                'button:has-text("Continue")',
            ],
        )
        page.wait_for_timeout(8000)
        dump_page(page, "after-submit")

        body = (page.evaluate("() => (document.body && document.body.innerText || '')") or "").lower()
        need_mail = any(
            x in body for x in ("check your email", "verify your email", "confirmation", "we sent", "inbox")
        ) or ("verify" in page.url)
        result["need_mail"] = need_mail
        result["url_after_submit"] = page.url
        if create_error:
            result["create_api"] = create_error
            if any("CAPTCHA" in x or x.startswith("400") for x in create_error) and not need_mail:
                result["error"] = "captcha_or_create_failed"
                return result

        if not need_mail and not create_error:
            # maybe still created; continue to dash fetch
            pass

        mail_timeout = int(os.environ.get("OTP_TIMEOUT", "180"))
        if not need_mail:
            mail_timeout = 20
        mail = poll_verify_mail(email, timeout=mail_timeout)
        result["mail"] = {k: mail.get(k) for k in ("id", "subject", "from", "links", "codes")}
        if not mail:
            result["error"] = "no_verify_mail"
            return result

        links = mail.get("links") or []
        codes = mail.get("codes") or []
        if links:
            vurl = links[0]
            log(f"open verify {vurl}")
            page.goto(vurl, timeout=90000, wait_until="domcontentloaded")
            page.wait_for_timeout(6000)
            dump_page(page, "after-verify-link")
        elif codes:
            code = codes[0]
            log(f"type code {code}")
            type_into(
                page,
                'input[name=code], input[autocomplete="one-time-code"], input[inputmode=numeric]',
                code,
                delay=40,
            )
            click_first(page, ['button[type=submit]', 'button:has-text("Verify")', 'button:has-text("Continue")'])
            page.wait_for_timeout(5000)
            dump_page(page, "after-code")

        # skip onboarding if present
        for _ in range(6):
            click_first(
                page,
                [
                    'button:has-text("Skip")',
                    'a:has-text("Skip")',
                    'button:has-text("I don\'t have a site")',
                    'button:has-text("Not now")',
                    'button:has-text("Get started")',
                    'button:has-text("Continue")',
                ],
                timeout=2500,
            )
            page.wait_for_timeout(1500)
            if re.search(r"/[a-f0-9]{32}", page.url):
                break

        dump_page(page, "post-onboard")
        result["final_url"] = page.url
        m = re.search(r"/([a-f0-9]{32})", page.url)
        if m:
            result["account_id"] = m.group(1)

        try:
            result["user_api"] = dash_fetch(page, "/api/v4/user")
        except Exception as exc:
            result["user_api_error"] = str(exc)
        try:
            result["accounts_api"] = dash_fetch(page, "/api/v4/accounts?page=1&per_page=20")
        except Exception as exc:
            result["accounts_api_error"] = str(exc)

        # try reveal global api key with password (dashboard session)
        try:
            key_resp = page.evaluate(
                """async (pw) => {
                  const r = await fetch('/api/v4/user/keys', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                    body: JSON.stringify({password: pw}),
                  });
                  const t = await r.text();
                  try { return {status: r.status, json: JSON.parse(t)}; }
                  catch (e) { return {status: r.status, text: t.slice(0, 400)}; }
                }""",
                password,
            )
            result["keys_api"] = key_resp
        except Exception as exc:
            result["keys_api_error"] = str(exc)

        cookies = []
        try:
            for c in context.cookies() or []:
                if c.get("name"):
                    cookies.append(
                        {
                            "name": c.get("name"),
                            "domain": c.get("domain"),
                            "path": c.get("path"),
                            "value": c.get("value"),
                        }
                    )
        except Exception:
            pass
        result["cookies"] = cookies
        result["ok"] = bool(result.get("account_id") or (result.get("user_api") or {}).get("status") == 200)
        if not result["ok"]:
            # still success if verify mail clicked and we are on dash
            if "dash.cloudflare.com" in (result.get("final_url") or "") and "sign-up" not in (result.get("final_url") or ""):
                result["ok"] = True
                result["error"] = result.get("error") or "logged_in_no_account_id"
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        log(f"FAIL {result['error']}")
        return result
    finally:
        try:
            if context:
                context.close()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass


def main() -> int:
    result = register()
    save(result)
    print(json.dumps({k: v for k, v in result.items() if k != "cookies"}, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
