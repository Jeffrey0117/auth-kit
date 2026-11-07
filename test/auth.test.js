// node --test "test/*.test.js"
const test = require("node:test");
const assert = require("node:assert/strict");
const createAuth = require("../index");

const auth = createAuth({ secret: "test-secret-not-a-real-one" });

test("secret 必填（不准 fallback 到公開預設值）", () => {
  assert.throws(() => createAuth({}), /secret is required/);
  assert.throws(() => createAuth({ secret: "" }), /secret is required/);
});

test("密碼雜湊：存的不是明碼,驗得回來,錯的驗不過", () => {
  const stored = auth.hashPassword("hunter2");
  assert.ok(!stored.includes("hunter2"));
  assert.match(stored, /^[0-9a-f]{32}:[0-9a-f]{128}$/);
  assert.equal(auth.verifyPassword("hunter2", stored), true);
  assert.equal(auth.verifyPassword("hunter3", stored), false);
  // 同一個密碼兩次雜湊要不同（salt 有在動）
  assert.notEqual(auth.hashPassword("hunter2"), stored);
});

test("verifyPassword 對垃圾輸入回 false,永不 throw", () => {
  for (const bad of [null, undefined, "", "nosalt", 42, {}]) {
    assert.equal(auth.verifyPassword("pw", bad), false);
  }
});

test("JWT：簽得出來、驗得回來、改過就失效", () => {
  const token = auth.signJWT({ sub: "u1", tier: "premium" });
  const payload = auth.verifyJWT(token);
  assert.equal(payload.sub, "u1");
  assert.equal(payload.tier, "premium");
  assert.equal(typeof payload.exp, "number");

  const [h, , s] = token.split(".");
  const evil = Buffer.from(JSON.stringify({ sub: "admin", exp: Date.now() + 1e6 })).toString("base64url");
  assert.equal(auth.verifyJWT(`${h}.${evil}.${s}`), null);
});

test("JWT：過期的擋掉", () => {
  assert.equal(auth.verifyJWT(auth.signJWT({ sub: "u1" }, -1000)), null);
});

test("🔒 字串型 exp 擋掉（舊版 `!payload.exp ||` 會讓它永不過期）", () => {
  // 攻擊前提是已握有 secret,所以可利用性低 —— 但這是同一類 fail-open:
  // `!"9"` 是 false、`"abc" < Date.now()` 也是 false（NaN 比較）→ 兩邊都躲過。
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const crypto = require("node:crypto");
  const forge = (exp) => {
    const input = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "attacker", exp })}`;
    const sig = crypto.createHmac("sha256", "test-secret-not-a-real-one").update(input).digest("base64url");
    return `${input}.${sig}`;
  };
  assert.equal(auth.verifyJWT(forge("99999999999999")), null, "字串 exp");
  assert.equal(auth.verifyJWT(forge("abc")), null, "非數字字串 exp");
  assert.equal(auth.verifyJWT(forge(Infinity)), null, "Infinity 會被 JSON 寫成 null");
  // 對照組：數字 exp 照常有效
  assert.ok(auth.verifyJWT(forge(Date.now() + 60000)));
});

test("🔒 alg 混淆 / none 擋掉", () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const h = b64({ alg: "none", typ: "JWT" });
  const p = b64({ sub: "admin", exp: Date.now() + 1e6 });
  assert.equal(auth.verifyJWT(`${h}.${p}.`), null);
  assert.equal(auth.verifyJWT(`${h}.${p}.anything`), null);
});

test("verifyJWT 對垃圾輸入回 null", () => {
  for (const bad of ["", "a", "a.b", null, undefined, 42]) {
    assert.equal(auth.verifyJWT(bad), null);
  }
});

test("tokenFromRequest：Bearer 與 cookie 都取得到", () => {
  assert.equal(auth.tokenFromRequest({ headers: { authorization: "Bearer abc" } }), "abc");
  assert.equal(auth.tokenFromRequest({ headers: { cookie: "session=abc; other=1" } }, "session"), "abc");
  assert.equal(auth.tokenFromRequest({ headers: { cookie: "other=1" } }, "session"), null);
  assert.equal(auth.tokenFromRequest({ headers: {} }), null);
  assert.equal(auth.tokenFromRequest({}), null);
});
