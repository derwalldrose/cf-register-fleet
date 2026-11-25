
#!/usr/bin/env python3
"""Finish Cloudflare email verification in the same Cloak session family."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cf_signup_cloak as cf  # noqa: E402

RESULT = Path(os.environ.get("CF_SIGNUP_OUT", "cf-signup-result.json"))


def main() -> int:
    d = json.loads(RESULT.read_text())
    links = ((d.get("mail") or {}).get("links") or [])
    vurl = next((u for u in links if "email-verification" in u), "")
    if not vurl:
        print("no verify url")
        return 1
    cf.log(f"verify {vurl[:80]}...")
    browser = cf.launch_browser()
    ctx_kwargs = {"viewport": {"width": 1280, "height": 1400}, "locale": "en-US"}
    if cf.PROXY:
        ctx_kwargs["proxy"] = {"server": cf.PROXY}
    context = browser.new_context(**ctx_kwargs)
    cookies = []
    for c in d.get("cookies") or []:
        if not c.get("name"):
            continue
        item = {
            "name": c["name"],
            "value": c.get("value") or "",
            "domain": c.get("domain") or ".cloudflare.com",
            "path": c.get("path") or "/",
        }
        cookies.append(item)
    try:
        context.add_cookies(cookies)
    except Exception as exc:
        cf.log(f"add_cookies: {exc}")
    page = context.new_page()
    try:
        page.goto(vurl, timeout=90000, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        cf.dump_page(page, "verify-goto")
        cf.click_human_widget(page)
        n = cf.wait_turnstile(page, seconds=25)
        cf.log(f"verify ts={n}")
        page.wait_for_timeout(4000)
        # maybe auto-continues; else click Verify
        cf.click_first(page, ['button:has-text("Verify")', 'button[type=submit]', 'button:has-text("Continue")'])
        page.wait_for_timeout(5000)
        cf.dump_page(page, "verify-after")
        info = cf.dash_fetch(page, "/api/v4/user")
        print(json.dumps(info, ensure_ascii=False)[:1500])
        verified = False
        if isinstance(info, dict):
            verified = bool(((info.get("json") or {}).get("result") or {}).get("email_verified"))
        d["email_verified"] = verified
        d["verify_followup"] = {"url": page.url, "user_api": info}
        RESULT.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n")
        cf.log(f"email_verified={verified}")
        return 0 if verified else 2
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

