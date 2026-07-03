// 最小範例：node example.js
const auth = require('./index')({ secret: 'demo-secret-換成你的私有值' });

// 密碼
const stored = auth.hashPassword('hunter2');
console.log('stored:', stored.slice(0, 34) + '...');
console.log('verify correct:', auth.verifyPassword('hunter2', stored)); // true
console.log('verify wrong:  ', auth.verifyPassword('nope', stored));    // false

// JWT
const jwt = auth.signJWT({ sub: 'user-42', tier: 'premium' });
console.log('jwt:', jwt.slice(0, 30) + '...');
console.log('verify jwt:      ', auth.verifyJWT(jwt));       // { sub, tier, iat, exp }
console.log('verify tampered: ', auth.verifyJWT(jwt + 'x')); // null
