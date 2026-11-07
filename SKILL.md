---
name: auth-kit
description: Use when a project needs to issue and verify ITS OWN sessions — "加註冊登入"、"存密碼"、"發 session token"、"自己做會員系統" — without pulling in bcrypt or jsonwebtoken. NOT for verifying tokens issued by an external identity provider (LetMeUse / Auth0 / Clerk): that is jwks-verify-kit.
---

# auth-kit 🔑 — 打法

**自架小專案的註冊登入兩件事：安全存密碼 + 發無狀態 session token。** 零依賴（node 內建 `crypto`）。

## 何時觸發

- 要做自己的會員系統（email + 密碼），不想裝 `bcrypt`（要編譯）或 `jsonwebtoken`
- 看到專案裡手寫 `crypto.pbkdf2` / `createHmac` 做 session → 換成這個 kit

## ⛔ 何時**不要**用

| 情境 | 正確的 kit |
|---|---|
| 驗外部 IdP（LetMeUse / Auth0 / Clerk）發的 access token | `jwks-verify-kit` |
| 機器對機器（MCP 工具、gateway 代打） | 不透明隨機字串 + `timingSafeEqual` |

為什麼分這麼清楚：對稱簽章（HS256）的驗證方必須握著簽發金鑰。自己發自己驗時那是你的 secret，沒差；但驗**別人**發的 token 時，等於你手上有一把能冒充任何使用者的鑰匙 —— 它一外洩，攻擊者就能自簽 `sub`/`role` 隨便填的 token 走進管理後台。Jeff 生態系 2026-10-25 的 pokkit 事件就是這樣。

機器憑證做成「自簽的一年期使用者 JWT」也是同一個錯誤的另一種穿法：它逼得驗證端必須保留對稱簽章路徑，又把機器假扮成人（areyoubot 的 `AREYOUBOT_SERVICE_TOKEN` 曾是這樣，已改成不透明 token）。

## 接線（照抄能跑）

```bash
npm i github:Jeffrey0117/auth-kit
```

```js
const auth = require('auth-kit')({ secret: process.env.JWT_SECRET });  // 私有值,別 fallback

// 註冊
await db.createUser({ email, password: auth.hashPassword(plainPw) });

// 登入
if (!auth.verifyPassword(plainPw, user.password)) return unauthorized();
const token = auth.signJWT({ sub: user.id, tier: user.tier });
res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Strict; Path=/`);

// 每個請求
const payload = auth.verifyJWT(auth.tokenFromRequest(req, 'session'));
if (!payload) return unauthorized();
```

## 模式與文案

- **cookie 一律 `HttpOnly; SameSite=Strict`**，正式站再加 `Secure`。放 localStorage 的話任何 XSS 都等於帳號接管。
- **`secret` 不准 fallback 到預設值**。公開 repo 裡寫死的「開發用 secret」上線後沒人記得換 —— 這在 Jeff 生態系發生過（reelscript、selfize 的 `selfize-dev-token`）。沒設就該讓它壞掉，或退到隨機值鎖死功能。
- **要「立刻登出/撤銷」就得自己加黑名單**。JWT 自帶到期、驗證不查 DB 是優點也是限制；`jwtExpiresMs` 設短一點是最便宜的緩解。
- 想提高強度調 `iterations`（預設 100k）與 `digest`。

## 地雷

- **`iat`/`exp` 是毫秒,不是 RFC 7519 的秒。** 自己發自己驗沒問題,但 jose 等第三方讀這種 token 會把 `exp` 當成西元五萬年。要跟外界互通必須先改單位 —— 改了會讓既有已發出的 token 全部失效。
- **`exp` 的檢查一定要先確認型別**。寫成 `!payload.exp || payload.exp < Date.now()` 的話,字串型 `exp` 會兩邊都躲過（`!"abc"` 是 false、`"abc" < Date.now()` 是 NaN 比較也是 false）→ 永不過期。已修（2026-11-08），有回歸測試。
- `verifyPassword` / `verifyJWT` **永不 throw**，一律回 `false`/`null` —— 別在外面包一層 try/catch 然後在 catch 裡放行。
