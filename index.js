// ============================================================================
// auth-kit — 無函式庫的驗證原語（PBKDF2 密碼雜湊 + HMAC-SHA256 JWT）
// ----------------------------------------------------------------------------
// ⛔ 守備範圍：這個 kit 是給「**自己**發 session」用的 —— 你是簽發者也是驗證
//    者,secret 兩邊都是你。
//
//    **不要拿它去驗別人家 IdP（LetMeUse / Auth0 / Clerk…）發的 token。**
//    那種情境用對稱簽章等於「驗證方必須握著簽發金鑰」,app secret 一外洩,
//    任何人都能自簽一顆 sub/role 隨便填的 token 冒充任何人（Jeff 生態系
//    2026-10-25 pokkit 事件根因）。那個情境請用:
//        github:Jeffrey0117/jwks-verify-kit   （ES256 + JWKS 公鑰,驗證方零 secret）
//
// ⚠️ iat/exp 的單位是**毫秒**（`Date.now()`）,不是 RFC 7519 的秒。自己發自己
//    驗沒問題,但任何第三方函式庫（jose 等）讀這種 token 會把 exp 當成西元
//    五萬年。要跟外界互通就得改單位 —— 改了會讓既有已發出的 token 全部失效,
//    所以目前刻意不動,在這裡記一筆。
// ----------------------------------------------------------------------------
// 零依賴（只用 node 內建 crypto）。不用 bcrypt / jsonwebtoken，一個檔搞定
// 註冊登入需要的兩件事：安全存密碼、發/驗無狀態 token。
// 比對一律 timingSafeEqual、JWT 檢查 alg（擋 alg 混淆）。
//
// 用法：
//   const auth = require('auth-kit')({ secret: process.env.JWT_SECRET });
//   const stored = auth.hashPassword(plainPw);            // 存進 DB
//   if (!auth.verifyPassword(plainPw, stored)) throw ...; // 登入
//   const jwt = auth.signJWT({ sub: user.id, tier: 'premium' });
//   const payload = auth.verifyJWT(auth.tokenFromRequest(req, 'session')); // null=無效
// ============================================================================
const crypto = require('crypto');

module.exports = function createAuth(opts = {}) {
  const secret = opts.secret;
  if (!secret) throw new Error('auth-kit: opts.secret is required (JWT/簽章密鑰，請用私有值)');
  const jwtExpiresMs = opts.jwtExpiresMs || 7 * 24 * 60 * 60 * 1000; // 預設 7 天
  const iterations = opts.iterations || 100000;
  const keylen = opts.keylen || 64;
  const digest = opts.digest || 'sha512';

  // 密碼雜湊：PBKDF2，回 "salt:hash"（存進 DB）。
  function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
    return `${salt}:${hash}`;
  }

  // 驗證密碼（constant-time 比對）。永不 throw。
  function verifyPassword(password, stored) {
    try {
      const [salt, hash] = String(stored).split(':');
      if (!salt || !hash) return false;
      const verify = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
      const a = Buffer.from(hash), b = Buffer.from(verify);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (e) { return false; }
  }

  // 發 JWT（HS256）。payload 會補上 iat/exp。
  function signJWT(payload, expiresInMs) {
    const now = Date.now();
    const exp = now + (expiresInMs || jwtExpiresMs);
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const p = Buffer.from(JSON.stringify({ ...payload, iat: now, exp })).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
    return `${h}.${p}.${sig}`;
  }

  // 驗 JWT：簽章(constant-time) + alg + 到期。回 payload 或 null。永不 throw。
  function verifyJWT(token) {
    try {
      if (!token) return null;
      const [h, p, sig] = String(token).split('.');
      if (!h || !p || !sig) return null;
      const expected = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
      const a = Buffer.from(sig), b = Buffer.from(expected);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
      const header = JSON.parse(Buffer.from(h, 'base64url').toString());
      if (header.alg !== 'HS256') return null; // 擋 alg 混淆 / none
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
      // exp 必須是數字。寫成 `!payload.exp ||` 的話,字串型 exp 會兩邊都躲過
      // （`!"abc"` 是 false、`"abc" < Date.now()` 也是 false）→ 永不過期。
      // signJWT 一律寫入數字,所以這條不會擋掉自己發的 token。
      if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return null;
      if (payload.exp < Date.now()) return null;
      return payload;
    } catch (e) { return null; }
  }

  // 從 Authorization: Bearer 或 cookie 取 token。
  function tokenFromRequest(req, cookieName) {
    const authHeader = req.headers && req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) return authHeader.slice(7);
    if (cookieName && req.headers && req.headers.cookie) {
      const m = req.headers.cookie.match(new RegExp('(?:^|;\\s*)' + cookieName + '=([^;]+)'));
      if (m) return decodeURIComponent(m[1]);
    }
    return null;
  }

  return { hashPassword, verifyPassword, signJWT, verifyJWT, tokenFromRequest };
};
