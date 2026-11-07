# auth-kit 🔑

**無函式庫的驗證原語。** PBKDF2 密碼雜湊 + HMAC-SHA256 JWT，一個檔搞定註冊登入。
**零依賴**（只用 node 內建 `crypto`）、比對一律 `timingSafeEqual`、JWT 檢查 `alg`（擋 alg 混淆/none）。

> 不用 `bcrypt`（要編譯原生模組）、不用 `jsonwebtoken`。自架/小專案要「安全存密碼 + 發無狀態 token」就這兩件事。

## ⛔ 守備範圍（先看這段）

這個 kit 是給「**自己**發 session」用的 —— 你同時是簽發者和驗證者,secret 兩邊都是你。

**不要拿它去驗別人家 IdP（LetMeUse / Auth0 / Clerk…）發的 token。** 那種情境用對稱簽章（HS256）等於「驗證方必須握著簽發金鑰」,app secret 一外洩,任何人都能自簽一顆 `sub`/`role` 隨便填的 token 冒充任何人,包含管理員。

| 你的情境 | 用哪個 |
|---|---|
| 自己存密碼、自己發 session | **auth-kit**（就是這個） |
| 驗外部 IdP 發的 access token | [**jwks-verify-kit**](https://github.com/Jeffrey0117/jwks-verify-kit)（ES256 + JWKS 公鑰,驗證方零 secret） |
| 機器對機器（MCP 工具、gateway） | 不透明隨機字串 + `timingSafeEqual`,**不要**自簽長期「使用者」JWT |

⚠️ `iat`/`exp` 的單位是**毫秒**（`Date.now()`）,不是 RFC 7519 的秒。自己發自己驗沒問題,但第三方函式庫（jose 等）讀這種 token 會把 `exp` 當成西元五萬年。改單位會讓既有已發出的 token 全部失效,所以目前刻意不動。

## 安裝

```bash
npm i github:Jeffrey0117/auth-kit     # 或直接複製 index.js（零依賴）
```

## 用法

```js
const auth = require('auth-kit')({ secret: process.env.JWT_SECRET }); // 私有 secret！

// 註冊：存雜湊，別存明碼
await db.createUser({ email, password: auth.hashPassword(plainPw) });

// 登入：驗密碼 → 發 token → 塞 cookie
if (!auth.verifyPassword(plainPw, user.password)) return unauthorized();
const token = auth.signJWT({ sub: user.id, tier: user.tier });
res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Strict; Path=/`);

// 之後每個請求：取 token → 驗 → 拿到 payload
const payload = auth.verifyJWT(auth.tokenFromRequest(req, 'session'));
if (!payload) return unauthorized();
// payload = { sub, tier, iat, exp }
```

## API

`createAuth({ secret, jwtExpiresMs?, iterations?, keylen?, digest? })` → 下列五個函式（`secret` 必填）

| 方法 | 說明 |
|---|---|
| `hashPassword(pw)` | PBKDF2（預設 100k 次 / sha512 / 64 bytes）→ `"salt:hash"` 存 DB。 |
| `verifyPassword(pw, stored)` | constant-time 比對。永不 throw，回 `true`/`false`。 |
| `signJWT(payload, expiresInMs?)` | HS256，自動補 `iat`/`exp`（預設 7 天）。 |
| `verifyJWT(token)` | 驗簽章(constant-time)+`alg`+到期 → payload 或 `null`。永不 throw。 |
| `tokenFromRequest(req, cookieName?)` | 從 `Authorization: Bearer` 或 cookie 取 token。 |

## 設計重點

- **`secret` 用私有值**（別 fallback 到公開/預設，否則 token 可偽造）。
- **timing-safe**：密碼與簽章比對都用 `crypto.timingSafeEqual`，不洩漏時間資訊。
- **擋 alg 混淆**：`verifyJWT` 只認 `HS256`，拒絕 `none` 之類的攻擊。
- **`exp` 必須是數字**：寫成 `!payload.exp ||` 的話字串型 `exp` 會兩邊都躲過（`!"abc"` 是 false、`"abc" < Date.now()` 也是 false）→ 永不過期。
- **無狀態**：JWT 自帶到期，驗證不用查 DB；要「立刻登出/撤銷」再自行加黑名單。
- 參數可調（`iterations`/`digest` 提高強度、`jwtExpiresMs` 改效期）。

## 測試

```bash
npm test
```

## License

MIT © Jeffrey0117
