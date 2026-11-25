
#!/usr/bin/env python3
"""Reveal Cloudflare Global API Key from a logged-in Cloak session."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cf_signup_cloak as cf  # noqa: E402

RESULT = Path(os.environ.get("CF_SIGNUP_OUT", "cf-signup-result.json"))
ACCOUNT = Path(os.environ.get("CF_ACCOUNT_JSON", "cf-account.json"))
OUT = Path(os.environ.get("CF_KEY_OUT", "cf-global-key.json"))
PROFILE_URL = "https://dash.cloudflare.com/profile/api-tokens"
HOME_URL = "https://dash.cloudflare.com/"


def load_creds() -> dict:
    d = {}
    if RESULT.exists():
        d = json.loads(RESULT.read_text())
    if ACCOUNT.exists():
        a = json.loads(ACCOUNT.read_text())
        d.setdefault("email", a.get("email"))
        d.setdefault("password", a.get("password"))
        d.setdefault("accountId", a.get("accountId"))
    return d


def save(obj: dict) -> None:
    OUT.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    cf.log(f"wrote {OUT}")


def snapshot_mailbox(email: str) -> set[str]:
    local = email.split("@", 1)[0]
    try:
        msgs = cf._get_json(f"{cf.INBUCKET_BASE}/api/v1/mailbox/{local}")
    except Exception as exc:
        cf.log(f"mailbox snapshot err: {exc}")
        return set()
    if not isinstance(msgs, list):
        return set()
    return {str(m.get("id") or "") for m in msgs if m.get("id")}


def poll_new_otp(email: str, seen: set[str], timeout: int = 120) -> dict:
    local = email.split("@", 1)[0]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            msgs = cf._get_json(f"{cf.INBUCKET_BASE}/api/v1/mailbox/{local}")
        except Exception as exc:
            cf.log(f"inbucket list err: {exc}")
            time.sleep(3)
            continue
        if not isinstance(msgs, list):
            time.sleep(3)
            continue
        cf.log(f"inbucket mailbox={local} n={len(msgs)} seen={len(seen)}")
        for m in msgs:
            mid = str(m.get("id") or "")
            if not mid or mid in seen:
                continue
            seen.add(mid)
            try:
                full = cf._get_json(f"{cf.INBUCKET_BASE}/api/v1/mailbox/{local}/{mid}")
            except Exception as exc:
                cf.log(f"inbucket read {mid} err: {exc}")
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
            cf.log(f"NEW mail id={mid} from={frm} subject={subj!r}")
            # CF identity codes are usually 6-8 digits, not all-zero
            # Identity OTP is 7 digits. Prefer 7 over 6 (signup-verify mails inject 000000).
            codes7 = re.findall(r"\b(\d{7})\b", text)
            codes68 = [c for c in re.findall(r"\b(\d{6,8})\b", text) if c.strip("0")]
            codes = codes7 + [c for c in codes68 if c not in codes7]
            m2 = re.search(r"(?:code|otp)[:\s]+([0-9]{6,8})", text, re.I)
            if m2 and m2.group(1) not in codes:
                codes.insert(0, m2.group(1))
            return {
                "id": mid,
                "subject": subj,
                "from": frm,
                "codes": codes[:6],
                "snippet": text[:800],
            }
        time.sleep(3)
    return {}


def extract_key(obj) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        m = re.search(r"\b(cfk_[A-Za-z0-9]+|[a-f0-9]{37,40})\b", obj)
        return m.group(1) if m else ""
    if isinstance(obj, dict):
        for k in ("api_key", "apiKey", "key", "result"):
            if k in obj:
                got = extract_key(obj[k])
                if got:
                    return got
        for v in obj.values():
            got = extract_key(v)
            if got:
                return got
    if isinstance(obj, list):
        for v in obj:
            got = extract_key(v)
            if got:
                return got
    return ""


def fetch_keys(page, password: str) -> list[dict]:
    return page.evaluate(
        """async (pw) => {
          const csrf = (document.cookie.match(/(?:^|; )vses2=([^;]+)/) || [])[1] || '';
          const paths = [
            '/api/v4/user/keys',
            '/api/v4/user/api-keys',
            '/api/v4/user/api_keys',
            '/api/v4/user/tokens',
          ];
          const headersBase = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-cross-site-security': 'dash',
            'Origin': 'https://dash.cloudflare.com',
            'Referer': location.href,
          };
          if (csrf) headersBase['x-atok'] = decodeURIComponent(csrf);
          const out = [];
          for (const path of paths) {
            for (const body of [{password: pw}, {api_key: {password: pw}}, {}]) {
              try {
                const r = await fetch(path, {
                  method: 'POST',
                  credentials: 'include',
                  headers: headersBase,
                  body: JSON.stringify(body),
                });
                const t = await r.text();
                let parsed = null;
                try { parsed = JSON.parse(t); } catch (e) {}
                out.push({
                  path, status: r.status,
                  body: body && Object.keys(body).length ? Object.keys(body) : [],
                  json: parsed,
                  text: parsed ? '' : t.slice(0, 220),
                });
              } catch (e) {
                out.push({path, error: String(e)});
              }
            }
          }
          try {
            const g = await fetch('/api/v4/user/keys', {credentials: 'include', headers: headersBase});
            const t = await g.text();
            let parsed = null;
            try { parsed = JSON.parse(t); } catch (e) {}
            out.push({path: 'GET /api/v4/user/keys', status: g.status, json: parsed, text: parsed ? '' : t.slice(0, 220)});
          } catch (e) {
            out.push({path: 'GET /api/v4/user/keys', error: String(e)});
          }
          return out;
        }""",
        password,
    )


def ui_reveal(page, email: str, password: str) -> dict:
    cf.dump_page(page, "profile")
    page.screenshot(path="/tmp/cf-api-tokens.png")
    cf.log("screenshot /tmp/cf-api-tokens.png")
    clicked = False
    try:
        loc = page.get_by_text("Global API Key", exact=False)
        if loc.count() > 0:
            loc.first.scroll_into_view_if_needed(timeout=5000)
            box = loc.first.bounding_box()
            cf.log(f"global-key label box={box}")
            row = page.locator("text=Global API Key").first.locator("xpath=ancestor::*[self::tr or self::div][1]")
            try:
                row.locator('button:has-text("View")').first.click(timeout=4000)
                clicked = True
                cf.log("clicked View in Global API Key row")
            except Exception as exc:
                cf.log(f"row view: {exc}")
                view = page.locator('button:has-text("View")')
                if view.count():
                    view.first.click(timeout=4000)
                    clicked = True
                    cf.log("clicked first View")
    except Exception as exc:
        cf.log(f"ui view: {exc}")
    page.wait_for_timeout(1500)
    cf.dump_page(page, "after-view")
    page.screenshot(path="/tmp/cf-api-tokens-after.png")

    # Identity step: email OTP (not password)
    if page.locator('button:has-text("Send Verification Code")').count():
        seen = snapshot_mailbox(email)
        cf.click_first(page, ['button:has-text("Send Verification Code")'])
        page.wait_for_timeout(2000)
        cf.dump_page(page, "after-send-code")
        mail = poll_new_otp(email, seen, timeout=int(os.environ.get("OTP_TIMEOUT", "120")))
        codes = [c for c in (mail.get("codes") or []) if c and c.strip("0")]
        if not codes:
            return {"clicked": clicked, "error": "no_otp", "mail": mail, "key_from_ui": ""}
        code = codes[0]
        cf.log(f"otp={code} mail_subj={mail.get('subject')!r}")
        typed = False
        for sel in (
            'input[name=code]',
            'input[autocomplete="one-time-code"]',
            'input[inputmode=numeric]',
            'input[type=text]',
        ):
            try:
                loc = page.locator(sel)
                for i in range(min(loc.count(), 4)):
                    el = loc.nth(i)
                    if not el.is_visible():
                        continue
                    el.click()
                    el.fill("")
                    el.type(code, delay=40)
                    typed = True
                    cf.log(f"typed otp into {sel}[{i}]")
                    break
                if typed:
                    break
            except Exception as exc:
                cf.log(f"otp fill {sel}: {exc}")
        if not typed:
            page.keyboard.type(code, delay=40)
            cf.log("typed otp via keyboard")
        ts = 0
        for attempt in range(3):
            ts = cf.wait_turnstile(page, seconds=20)
            cf.log(f"apikey turnstile attempt={attempt+1} token_len={ts}")
            if ts > 50:
                break
            cf.click_human_widget(page)
            page.wait_for_timeout(2000)
        if ts <= 50:
            cf.log("WARN apikey turnstile empty — still clicking View")
        cf.click_first(
            page,
            [
                'button[type=submit]:has-text("View")',
                'button:has-text("Verify code")',
                'button:has-text("Verify")',
            ],
        )
        page.wait_for_timeout(4000)
        cf.dump_page(page, "after-otp")
        # If still on the 7-digit modal, one more widget click + View.
        still_code = page.locator('input[name=code]').count() > 0 and page.locator('input[name=code]').first.is_visible()
        has_key_box = page.locator('textarea[name=api_key]').count() > 0
        if still_code and not has_key_box:
            cf.log("still on OTP modal — retry widget+View")
            cf.click_human_widget(page)
            cf.wait_turnstile(page, seconds=16)
            cf.click_first(page, ['button[type=submit]:has-text("View")', 'button:has-text("Verify code")'])
            page.wait_for_timeout(4000)
            cf.dump_page(page, "after-otp-retry")

    # fallback password modal
    try:
        pw = page.locator('input[type=password]')
        if pw.count() > 0 and pw.first.is_visible():
            pw.first.click()
            pw.first.fill("")
            pw.first.type(password, delay=25)
            cf.log("typed password in modal")
            cf.click_first(
                page,
                [
                    'button:has-text("View")',
                    'button:has-text("Confirm")',
                    'button:has-text("Continue")',
                    'button[type=submit]',
                ],
            )
            page.wait_for_timeout(2500)
    except Exception as exc:
        cf.log(f"modal: {exc}")
    cf.dump_page(page, "after-confirm")
    page.screenshot(path="/tmp/cf-api-tokens-key.png")
    key = (
        page.evaluate(
            """() => {
              const el = document.querySelector('textarea[name="api_key"], input[name="api_key"]');
              return (el && el.value || '').trim();
            }"""
        )
        or ""
    )
    body = page.evaluate("() => (document.body && document.body.innerText) || ''") or ""
    if not key:
        key = extract_key(body)
    cf.log(f"key_from_ui len={len(key)}")
    return {"clicked": clicked, "key_from_ui": key, "body_tail": body[-400:]}


def main() -> int:
    creds = load_creds()
    email = creds.get("email") or ""
    password = creds.get("password") or ""
    cookies = creds.get("cookies") or []
    out = {"ok": False, "email": email, "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if not email or not password:
        out["error"] = "missing creds"
        save(out)
        return 1

    captured: list[dict] = []

    def on_resp(resp) -> None:
        try:
            url = resp.url
            if not any(
                x in url
                for x in (
                    "/keys",
                    "api-token",
                    "api_token",
                    "api-keys",
                    "captcha",
                    "profile",
                    "apikey",
                    "identity",
                    "verification",
                    "challenge",
                )
            ):
                return
            status = resp.status
            txt = ""
            try:
                txt = resp.text()[:400]
            except Exception:
                pass
            cf.log(f"HTTP {status} {url[:160]} {txt[:160]}")
            captured.append({"status": status, "url": url[:200], "text": txt[:400]})
        except Exception:
            pass

    browser = cf.launch_browser()
    ctx_kwargs = {"viewport": {"width": 1280, "height": 1400}, "locale": "en-US"}
    if cf.PROXY:
        ctx_kwargs["proxy"] = {"server": cf.PROXY}
    context = browser.new_context(**ctx_kwargs)
    if cookies:
        try:
            context.add_cookies(
                [
                    {
                        "name": c["name"],
                        "value": c.get("value") or "",
                        "domain": c.get("domain") or ".cloudflare.com",
                        "path": c.get("path") or "/",
                    }
                    for c in cookies
                    if c.get("name")
                ]
            )
            cf.log(f"loaded {len(cookies)} cookies")
        except Exception as exc:
            cf.log(f"add_cookies: {exc}")
    page = context.new_page()
    page.on("response", on_resp)
    try:
        last_err = None
        for attempt in range(3):
            try:
                page.goto(HOME_URL, timeout=60000, wait_until="domcontentloaded")
                last_err = None
                break
            except Exception as exc:
                last_err = exc
                cf.log(f"home goto {attempt+1}/3: {exc}")
                page.wait_for_timeout(2000)
        if last_err is not None:
            raise last_err
        page.wait_for_timeout(5000)
        cf.dump_page(page, "home")
        if "login" in page.url or "sign-up" in page.url:
            cf.log("session dead — login")
            page.goto("https://dash.cloudflare.com/login", timeout=90000, wait_until="domcontentloaded")
            page.wait_for_timeout(4000)
            cf.dump_page(page, "login")
            cf.type_into(page, 'input[name=email], input[type=text][name=email], input[type=email]', email)
            cf.type_into(page, 'input[name=password], input[type=password]', password, delay=25)
            cf.wait_turnstile(page, seconds=30)
            cf.click_first(page, ['button[type=submit]:has-text("Log in")', 'button:has-text("Log in")', 'button[type=submit]'])
            page.wait_for_timeout(8000)
            cf.dump_page(page, "after-login")

        page.goto(PROFILE_URL, timeout=90000, wait_until="domcontentloaded")
        page.wait_for_timeout(6000)
        cf.dump_page(page, "tokens-page")
        key = ""
        ui = ui_reveal(page, email, password)
        out["ui"] = {k: v for k, v in ui.items() if k != "body_tail"}
        out["ui_body_tail"] = ui.get("body_tail")
        key = ui.get("key_from_ui") or ""
        if not key:
            tries2 = fetch_keys(page, password)
            out["api_tries_after_ui"] = [
                {k: v for k, v in t.items() if k != "json"} | {"json_snip": json.dumps(t.get("json"), ensure_ascii=False)[:240] if t.get("json") is not None else None}
                for t in (tries2 or [])
            ]
            for t in tries2 or []:
                key = extract_key(t.get("json")) or extract_key(t.get("text"))
                if key:
                    break
        out["captured"] = captured[-20:]
        out["final_url"] = page.url
        if key:
            out["ok"] = True
            out["globalApiKey"] = key
            # persist into account json
            acc = {}
            if ACCOUNT.exists():
                acc = json.loads(ACCOUNT.read_text())
            acc.update(
                {
                    "email": email,
                    "password": password,
                    "globalApiKey": key,
                    "authType": "global_key",
                }
            )
            user = ((creds.get("user_api") or {}).get("json") or {}).get("result") or {}
            accts = ((creds.get("accounts_api") or {}).get("json") or {}).get("result") or []
            if user.get("id"):
                acc["userId"] = user["id"]
            if accts and accts[0].get("id"):
                acc["accountId"] = accts[0]["id"]
                acc["accountName"] = accts[0].get("name")
            acc["name"] = email.split("@")[0]
            ACCOUNT.write_text(json.dumps(acc, ensure_ascii=False, indent=2) + "\n")
            cf.log(f"updated {ACCOUNT}")
        else:
            out["error"] = "no_key"
        save(out)
        print(json.dumps({k: v for k, v in out.items() if k not in ("captured",)}, ensure_ascii=False, indent=2)[:4000])
        return 0 if out.get("ok") else 2
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        save(out)
        cf.log(f"FAIL {out['error']}")
        return 1
    finally:
        try:
            context.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
