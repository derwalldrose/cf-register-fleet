# CF Register Fleet

批量注册 Cloudflare 账号的脚本集:用反指纹浏览器(CloakBrowser)过 Turnstile 挑战,
自建 Inbucket 邮箱收验证码,最后把账号 + Global API Key 落盘。

## 原理

三层配合才能稳定过 CF:

1. **反指纹浏览器** — 原版 Playwright Chromium 的 JS 环境指纹
   (WebGL/canvas/navigator/webdriver 痕迹)会被 Turnstile 直接判机器人。
   本项目用 [CloakBrowser](https://github.com) 这类修补过反检测的 Chromium,
   并开 `humanize=True, human_preset="careful"`:鼠标走曲线轨迹、点击带抖动延迟、
   操作节奏拟人,行为特征也接近真人。
2. **干净出口代理** — 浏览器流量全部走 `PROXY`(socks5)。IP 信誉、指纹、
   locale、时区必须自洽,出口 IP 频繁轮换,否则会被按"同 IP 批量注册"风控。
   **注意:收邮件的 Inbucket 查询永远不走代理**(脚本里强制剥掉 proxy env),
   只读本地/自建邮箱服务。
3. **Turnstile 自动交互** — `cf_signup_cloak.py` 定位 "Verify you are human"
   checkbox(含 iframe 内 fallback),模拟人点,轮询
   `cf-turnstile-response` input 的 value 长度拿到 token;
   邮箱验证和取 API Key 环节会再各过一次 Turnstile,逻辑相同。

## 流程

```
run_fleet_batch.sh            按 domains 文件生成邮箱列表, 逐个账号跑:
  ├─ cf_signup_cloak.py       开 sign-up 页 → 填邮箱/密码 → 过 Turnstile
  │                           → 提交 → Inbucket 轮询验证邮件 → 点验证链接
  │                           → 跳过 onboarding → 抓 account_id + cookies
  ├─ cf_verify_email.py       复用 cookies 再开验证链接, 确认 email_verified
  └─ cf_get_global_key.py     登录 dash → Profile/API Tokens → "View" Global API Key
                              → 过 Identity 二次验证(邮件 OTP)→ 读 key
                              → 写 account.json {email,password,accountId,globalApiKey}
```

成功账号追加到 `cf-batch/accounts.jsonl`,断点续跑:已有 key 的邮箱自动 skip。

## 前置

- Linux(默认走 xvfb 虚拟显示;`CLOAK_HEADLESS=1` 可无头)
- `xvfb-run`(xorg xvfb 包)、`xvfb` 屏幕 1280x1400
- Python ≥3.10 + `cloakbrowser`(自带 stealth Chromium 下载器)
- 一个 Inbucket 实例,catch-all 收 `CF_EMAIL_HOST` 的邮件
- 干净的 socks5 出口代理(自建隧道池/住宅代理均可)

```bash
pip install cloakbrowser
cloakbrowser fetch   # 下载 stealth chromium
```

## 使用

```bash
cp fleet.env.example fleet.env   # 填 PROXY / INBUCKET_* / CF_EMAIL_HOST
cp domains.example.json mydomains.json
set -a; source fleet.env; set +a
CF_DOMAINS_FILE=./mydomains.json CF_EMAIL_FROM=1 CF_EMAIL_TO=10 ./run_fleet_batch.sh
```

域名文件格式:`[{"idx":1,"host":"inbox.example.com","prefix":"cf01"}]`,
生成邮箱 `cf0101@host` … `cf0110@host`(prefix + 两位序号)。
本地部分必须全局唯一,且建议保持 `cf` + 数字 的形状。

## 输出

`cf-batch/<localpart>/`:
- `signup.json` — 注册过程(邮箱/密码/cookies/account_id/turnstile 长度)
- `account.json` — 最终记录,`globalApiKey` 非空即成功
- `key.json` — 取 key 的原始响应(排障用)

## 排障

- `no_verify_mail` — 检查 Inbucket 是否真的收到(`curl -u user:pass $INBUCKET_API_BASE/api/v1/mailbox/<localpart>`),
  以及 `CF_EMAIL_HOST` 的 MX/DNS 是否指向 Inbucket 前端的域名解析。
- Turnstile token 一直 0 — 出口 IP 信誉差/代理延迟大,换出口;或 `CF_SHOT=1`
  看 `/tmp/cf-signup-widget.png` 确认点没点到 checkbox。
- 注册成功但取 key 失败(常见 `sso/connector 400`)— CF 对 Identity 二次验证
  偶发风控,重跑该邮箱即可(driver 只跳过已拿到 key 的)。
- 整批 0 成功 — 大概率是出口池或机器指纹问题,先单账号 `CF_SHOT=1` 跑一个看截图。
