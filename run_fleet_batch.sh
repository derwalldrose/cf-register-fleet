#!/bin/bash
# Fleet driver: register a range of emails from a domains file, sequentially.
#
# Required env:
#   CF_DOMAINS_FILE   JSON list of {idx, suffix, host, prefix} — one mailbox prefix per host
#   INBUCKET_API_BASE Inbucket REST base URL (catch-all mailboxes)
#   INBUCKET_USER / INBUCKET_PASSWORD   Inbucket basic auth
#   CF_EMAIL_HOST     domain of the catch-all mailboxes
#   PROXY             outbound proxy for the browser, e.g. socks5://1.2.3.4:1080
#                     (must be a clean, human-like exit; one browser session per account)
#
# Optional env:
#   CF_EMAIL_FROM / CF_EMAIL_TO   register accounts #FROM..#TO on each host (1-based)
#   CF_SKIP_HOSTS                 space-separated host substrings to skip
#   CLOAKBROWSER_BINARY_PATH      stealth chromium binary
#   TURNSTILE_PATCH               optional extra extension dir
#   CLOAK_HEADLESS                default 0 (xvfb virtual display; more reliable)
#   OTP_TIMEOUT                   seconds to wait for verification mails (default 120)
#   CF_REG_TIMEOUT                per-stage wall timeout, seconds (default 900)
#   CF_SHOT                       screenshot each captcha step (default 0)
#   CF_FIXED_EMAIL                set internally per account (do not set manually)
#   PY                            python with cloakbrowser installed (default python3)
#   CF_BATCH_DIR                  output dir (default ./cf-batch)
#
# Per account output in $CF_BATCH_DIR/<localpart>/ :
#   signup.json   registration result (email, password, cookies, account id)
#   account.json  final record: email/password/accountId/globalApiKey
#   key.json      API key retrieval result
# Accounts are appended to $CF_BATCH_DIR/accounts.jsonl when the key is saved.
set -u
export TZ=Asia/Shanghai
export CLOAKBROWSER_BINARY_PATH="${CLOAKBROWSER_BINARY_PATH:-$HOME/.cloakbrowser/latest/chrome}"
export CLOAK_HEADLESS="${CLOAK_HEADLESS:-0}"
export TURNSTILE_PATCH="${TURNSTILE_PATCH:-}"
export OTP_TIMEOUT="${OTP_TIMEOUT:-120}"
export CF_SHOT="${CF_SHOT:-0}"
PY="${PY:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${CF_BATCH_DIR:-$HERE/cf-batch}"
DOMAINS="${CF_DOMAINS_FILE:?set CF_DOMAINS_FILE}"
FROM="${CF_EMAIL_FROM:-1}"
TO="${CF_EMAIL_TO:-10}"
SKIP_HOSTS="${CF_SKIP_HOSTS:-}"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/fleet.log"
JSONL="$OUTDIR/accounts.jsonl"
touch "$JSONL" "$LOG"

xvfb() { xvfb-run -a -s '-screen 0 1280x1400x24' "$@"; }

one_email() {
  local email="$1"
  local localpart="${email%%@*}"
  local dir="$OUTDIR/$localpart"
  mkdir -p "$dir"
  export CF_FIXED_EMAIL="$email"
  export CF_SIGNUP_OUT="$dir/signup.json"
  export CF_ACCOUNT_JSON="$dir/account.json"
  export CF_KEY_OUT="$dir/key.json"
  if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get('globalApiKey') else 1)" "$CF_ACCOUNT_JSON" 2>/dev/null; then
    echo "[skip] $email already has key"
    return 0
  fi
  echo "===== REGISTER $email ====="
  xvfb timeout --signal=KILL "${CF_REG_TIMEOUT:-900}" "$PY" -u "$HERE/cf_signup_cloak.py" register
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[fail] register $email rc=$rc"
    echo "{\"email\":\"$email\",\"stage\":\"register\",\"ok\":false}" >> "$JSONL"
    return 1
  fi
  echo "===== VERIFY $email ====="
  xvfb timeout --signal=KILL "${CF_REG_TIMEOUT:-900}" "$PY" -u "$HERE/cf_verify_email.py" || true
  echo "===== KEY $email ====="
  xvfb timeout --signal=KILL "${CF_REG_TIMEOUT:-900}" "$PY" -u "$HERE/cf_get_global_key.py"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[fail] key $email rc=$rc"
    echo "{\"email\":\"$email\",\"stage\":\"key\",\"ok\":false}" >> "$JSONL"
    return 1
  fi
  python3 - "$CF_ACCOUNT_JSON" "$JSONL" <<'PY'
import json,sys
a=json.load(open(sys.argv[1]))
a["ok"]=True
open(sys.argv[2],"a").write(json.dumps(a,ensure_ascii=False)+"\n")
print("SAVED", a.get("email"), "acct", a.get("accountId"), "key", str(a.get("globalApiKey",""))[:8])
PY
}

{
  echo "start $(date -Iseconds) domains=$DOMAINS from=$FROM to=$TO"
  python3 - "$DOMAINS" "$FROM" "$TO" "$SKIP_HOSTS" <<'PY' | while IFS=$'\t' read -r email host prefix; do
import json,sys
docs=json.load(open(sys.argv[1]))
fr,to=int(sys.argv[2]),int(sys.argv[3])
skip=[s for s in sys.argv[4].split() if s]
for d in docs:
    host=d["host"]; prefix=d["prefix"]
    if any(s in host for s in skip):
        continue
    for n in range(fr, to+1):
        print(f"{prefix}{n:02d}@{host}\t{host}\t{prefix}")
PY
    [ -n "$email" ] || continue
    one_email "$email" || echo "continue after fail $email"
  done
  echo "done $(date -Iseconds)"
  python3 - "$JSONL" <<'PY'
import json,sys
ok=fail=0
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    mark="OK" if d.get("ok") and d.get("globalApiKey") else "FAIL"
    if mark=="OK": ok+=1
    else: fail+=1
print(f"--- jsonl ok={ok} fail={fail}")
PY
} 2>&1 | tee -a "$LOG"
