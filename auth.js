// =============================================
//  AUTH TOKENS — stateless, signed sessions
// =============================================
// A lightweight HMAC-signed token so the server can trust who is calling and
// which branch they belong to WITHOUT a client being able to forge or edit it.
// No external dependency — uses Node's built-in crypto.
//
// Token format:  base64url(payloadJSON) + "." + base64url(HMAC-SHA256)
// Payload:       { uid, role, bid, exp }   (bid = branchId, null for admins)
//
// Set AUTH_SECRET in the environment for production. The dev fallback keeps
// local development working but must NOT be relied on in production.

const crypto = require('crypto');

const SECRET = process.env.AUTH_SECRET || 'dev-only-insecure-secret-change-me';
const TTL_MS = 1000 * 60 * 60 * 12; // 12 hours

function b64url(buf) {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(data) {
    return b64url(crypto.createHmac('sha256', SECRET).update(data).digest());
}

// Create a signed token for a user. `bid` (branchId) is embedded so every
// later request is scoped server-side, never by client-supplied values.
function signToken({ uid, role, bid }) {
    const payload = { uid, role, bid: bid || null, exp: Date.now() + TTL_MS };
    const body = b64url(JSON.stringify(payload));
    return `${body}.${sign(body)}`;
}

// Verify signature + expiry. Returns the payload, or null when invalid.
function verifyToken(token) {
    if (typeof token !== 'string' || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    if (!body || !sig) return null;

    // Constant-time compare to avoid signature timing leaks.
    const expected = sign(body);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    let payload;
    try {
        payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    } catch (e) {
        return null;
    }
    if (!payload || typeof payload.exp !== 'number' || payload.exp < Date.now()) return null;
    return payload;
}

module.exports = { signToken, verifyToken };
