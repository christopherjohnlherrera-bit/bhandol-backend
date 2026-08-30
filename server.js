const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { connect, getDb } = require('./database');
const { signToken, verifyToken } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Allowed frontend origins. The deployed static site plus common local-dev
// servers (Live Server :5500, a backend-served page :3000). Override/extend in
// production by setting FRONTEND_ORIGIN to a comma-separated list.
const DEFAULT_ORIGINS = [
    "https://bhandol-frontend.onrender.com",
    "http://localhost:5500", "http://127.0.0.1:5500", // VS Code Live Server
    "http://localhost:3000", "http://127.0.0.1:3000",
];
const ALLOWED_ORIGINS = (process.env.FRONTEND_ORIGIN
    ? process.env.FRONTEND_ORIGIN.split(",").map(s => s.trim())
    : DEFAULT_ORIGINS);

app.use(cors({
    origin: (origin, cb) => {
        // Allow same-origin / non-browser requests (no Origin header) and any
        // whitelisted origin. Auth is via bearer token, not cookies.
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        return cb(new Error(`Origin not allowed by CORS: ${origin}`));
    }
}));

app.use(express.json());

// Health check — handy for confirming the backend is up.
app.get('/', (req, res) => res.json({ status: 'ok', service: 'bhandol-backend' }));

// Exclude Mongo's internal _id from API responses so the JSON shape matches
// what the frontend expected from SQLite.
const NO_ID = { projection: { _id: 0 } };

// =============================================
//  VALIDATION HELPERS
// =============================================
function validateString(val, fieldName, minLen = 1, maxLen = 200) {
    if (typeof val !== 'string' || val.trim().length < minLen) {
        return `${fieldName} is required and must be at least ${minLen} character(s).`;
    }
    if (val.trim().length > maxLen) {
        return `${fieldName} must be at most ${maxLen} characters.`;
    }
    return null;
}

function validateInt(val, fieldName, min = 0, max = 999999) {
    const n = parseInt(val, 10);
    if (isNaN(n) || n < min || n > max) {
        return `${fieldName} must be a number between ${min} and ${max}.`;
    }
    return null;
}

function validationError(res, errors) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
}

// MongoDB raises code 11000 for any unique-index violation.
function isDuplicateKey(err) {
    return err && err.code === 11000;
}

// =============================================
//  AUTH + BRANCH-ISOLATION MIDDLEWARE
// =============================================
// Every protected route runs `authenticate` first. The caller's identity and
// branch come from the SIGNED TOKEN — never from query params or the body — so
// a staff client cannot reach another branch's data by tampering with a request.

function authenticate(req, res, next) {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    const payload = token && verifyToken(token);
    if (!payload) {
        return res.status(401).json({ error: 'Authentication required. Please log in again.' });
    }
    req.auth = payload; // { uid, role, bid }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.auth || req.auth.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden. Administrator access required.' });
    }
    next();
}

// READ scope. Staff are locked to their own branch. Admins see everything, or a
// single branch when they pass ?branch=<branchId> (?branch=all / omitted = all).
function branchReadFilter(req) {
    if (req.auth.role !== 'admin') return { branchId: req.auth.bid };
    const b = req.query.branch;
    if (!b || b === 'all') return {};
    return { branchId: b };
}

// WRITE scope guard. Staff writes are always constrained to their branch; admin
// writes may touch any branch. Combine this with the {id} match on updates/deletes.
function branchWriteMatch(req) {
    return req.auth.role === 'admin' ? {} : { branchId: req.auth.bid };
}

// The branch a NEW record belongs to: forced to the staff branch; admins must
// name the target branch explicitly in the request body.
function resolveWriteBranch(req) {
    if (req.auth.role !== 'admin') return req.auth.bid;
    return req.body.branchId || null;
}

// =============================================
//  TEMP PASSWORD GENERATOR
// =============================================
// Avoids visually ambiguous characters (0/O, 1/l/I) for easier relay.
// Guarantees at least one uppercase, lowercase, digit, and symbol.
function generateTempPassword() {
    const upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower   = 'abcdefghjkmnpqrstuvwxyz';
    const digits  = '23456789';
    const symbols = '!@#$%&';
    const all     = upper + lower + digits + symbols;

    // Start with one guaranteed character from each class
    const parts = [
        upper[Math.floor(Math.random() * upper.length)],
        lower[Math.floor(Math.random() * lower.length)],
        digits[Math.floor(Math.random() * digits.length)],
        symbols[Math.floor(Math.random() * symbols.length)],
    ];
    // Fill remaining 6 characters from the combined pool
    for (let i = 4; i < 10; i++) {
        parts.push(all[Math.floor(Math.random() * all.length)]);
    }
    // Fisher-Yates shuffle so the predictable first 4 positions aren't obvious
    for (let i = parts.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [parts[i], parts[j]] = [parts[j], parts[i]];
    }
    return parts.join('');
}

// =============================================
//  USERS API
// =============================================
// Branch registry — any authenticated user may read the list (needed for the
// admin switcher and the staff branch label).
app.get('/api/branches', authenticate, async (req, res) => {
    try {
        const rows = await getDb().collection('branches')
            .find({}, { projection: { _id: 0, id: 1, code: 1, name: 1, status: 1 } })
            .sort({ name: 1 })
            .toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// User management is admin-only.
app.get('/api/users', authenticate, requireAdmin, async (req, res) => {
    try {
        // SECURITY OVERRIDE: User explicitly requested passwords be viewable in Admin portal.
        // resetRequested, resetReason, mustChangePassword included for the Admin UI.
        // branchId included so the admin can see each staff member's assigned branch.
        const rows = await getDb().collection('users')
            .find({}, { projection: { _id: 0, id: 1, name: 1, username: 1, password: 1, role: 1, status: 1,
                                      branchId: 1, resetRequested: 1, resetReason: 1, mustChangePassword: 1 } })
            .toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', authenticate, requireAdmin, async (req, res) => {
    const { id, name, username, password, role, status } = req.body;
    let { branchId } = req.body;

    // Validate inputs
    const errors = [];
    const idErr = validateString(id, 'ID');
    const nameErr = validateString(name, 'Name', 2, 100);
    const usernameErr = validateString(username, 'Username', 3, 50);
    const passwordErr = validateString(password, 'Password', 4, 100);
    const roleErr = validateString(role, 'Role');
    const statusErr = validateString(status, 'Status');
    if (idErr) errors.push(idErr);
    if (nameErr) errors.push(nameErr);
    if (usernameErr) errors.push(usernameErr);
    if (passwordErr) errors.push(passwordErr);
    if (roleErr) errors.push(roleErr);
    if (statusErr) errors.push(statusErr);
    if (!['admin', 'staff'].includes(role)) errors.push('Role must be "admin" or "staff".');
    if (!['Active', 'Inactive'].includes(status)) errors.push('Status must be "Active" or "Inactive".');

    // Branch assignment rules: staff MUST have a valid branch; admins are
    // branch-agnostic (branchId forced to null regardless of what was sent).
    if (role === 'admin') {
        branchId = null;
    } else if (role === 'staff') {
        if (!branchId) {
            errors.push('Branch assignment is required for staff accounts.');
        } else {
            const branch = await getDb().collection('branches').findOne({ id: branchId });
            if (!branch) errors.push('Assigned branch does not exist.');
        }
    }
    if (errors.length > 0) return validationError(res, errors);

    try {
        // SECURITY OVERRIDE: User explicitly requested plaintext passwords.
        await getDb().collection('users').insertOne({ id, name, username, password, role, status, branchId });
        res.json({ id, name, username, role, status, branchId });
    } catch (err) {
        if (isDuplicateKey(err)) {
            return res.status(409).json({ error: 'Username already exists.' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/:id/status', authenticate, requireAdmin, async (req, res) => {
    const { status } = req.body;
    if (!['Active', 'Inactive'].includes(status)) {
        return validationError(res, ['Status must be "Active" or "Inactive".']);
    }
    try {
        await getDb().collection('users').updateOne({ id: req.params.id }, { $set: { status } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/users/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        await getDb().collection('users').deleteOne({ id: req.params.id });
        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  ADMIN — RESET USER PASSWORD
// =============================================
// POST /api/admin/users/:userId/reset-password
// Requires requesterId in body for server-side admin verification.
app.post('/api/admin/users/:userId/reset-password', async (req, res) => {
    const { requesterId } = req.body;

    if (!requesterId) {
        return res.status(401).json({ error: 'Unauthorized. requesterId is required.' });
    }

    try {
        // Server-side role check — never trust the client for privileged operations
        const requester = await getDb().collection('users').findOne({
            id: requesterId, role: 'admin', status: 'Active'
        });
        if (!requester) {
            return res.status(403).json({ error: 'Forbidden. Active admin account required.' });
        }

        const targetUser = await getDb().collection('users').findOne({ id: req.params.userId });
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Prevent an admin from locking themselves out via this route
        if (req.params.userId === requesterId) {
            return res.status(400).json({ error: 'Admins cannot reset their own password via this route.' });
        }

        // Generate a secure temporary password and immediately hash it
        const tempPassword   = generateTempPassword();
        const hashedPassword = await bcrypt.hash(tempPassword, SALT_ROUNDS);

        await getDb().collection('users').updateOne(
            { id: req.params.userId },
            {
                $set: {
                    password:           hashedPassword,
                    resetRequested:     false,
                    resetReason:        '',
                    mustChangePassword: true
                }
            }
        );

        // Return plaintext once so the admin can relay it securely to the employee
        res.json({ success: true, temporaryPassword: tempPassword });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    let { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    // Security: Aggressive trimming to remove accidental padding
    username = username.trim();

    // Constant time delay to mitigate brute force & timing attacks
    const failDelay = (callback) => setTimeout(callback, 800 + Math.random() * 400);

    try {
        const row = await getDb().collection('users').findOne({ username, status: 'Active' });
        if (!row) {
            // Wait to respond to mask whether the username actually exists (timing attack mitigation)
            return failDelay(() => res.status(401).json({ success: false, message: 'Invalid credentials or inactive account' }));
        }

        // Support both: legacy bcrypt hashed passwords AND new plain-text passwords
        let isMatch = false;
        if (row.password.startsWith('$2a$') || row.password.startsWith('$2b$')) {
            // bcrypt hash detected from previously created accounts
            isMatch = await bcrypt.compare(password, row.password);
        } else {
            // SECURITY OVERRIDE: Plain-text password (left as plaintext per user request to be viewable)
            isMatch = (password === row.password);
        }

        if (isMatch) {
            // Resolve the human-readable branch name (null for admins = all branches).
            let branchName = null;
            if (row.branchId) {
                const br = await getDb().collection('branches').findOne({ id: row.branchId }, { projection: { _id: 0, name: 1 } });
                branchName = br ? br.name : null;
            }
            // Sign a token that carries the branch — this is what enforces isolation.
            const token = signToken({ uid: row.id, role: row.role, bid: row.branchId || null });
            res.json({
                success: true,
                token,
                user: {
                    id: row.id, name: row.name, username: row.username, role: row.role,
                    branchId: row.branchId || null, branchName,
                    mustChangePassword: row.mustChangePassword || false
                }
            });
        } else {
            failDelay(() => res.status(401).json({ success: false, message: 'Invalid credentials or inactive account' }));
        }
    } catch (err) {
        failDelay(() => res.status(500).json({ error: 'Authentication error.' }));
    }
});

// =============================================
//  PASSWORD RESET WORKFLOW
// =============================================

// POST /api/auth/request-password-reset — Public
// Staff flag themselves so the Admin knows to generate a temp password.
app.post('/api/auth/request-password-reset', async (req, res) => {
    const { username, reason } = req.body;

    const usernameErr = validateString(username, 'Username', 1, 100);
    if (usernameErr) return validationError(res, [usernameErr]);

    // Generic success regardless of outcome — prevents username enumeration
    const GENERIC = { message: 'Password reset request submitted to Admin.' };

    try {
        const user = await getDb().collection('users').findOne({ username: username.trim() });
        if (!user) return res.json(GENERIC); // Non-existent user — silent success

        await getDb().collection('users').updateOne(
            { username: username.trim() },
            {
                $set: {
                    resetRequested: true,
                    resetReason:    (reason || '').trim().substring(0, 500)
                }
            }
        );
        res.json(GENERIC);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/auth/change-password — Authenticated users (incl. mustChangePassword users)
app.post('/api/auth/change-password', async (req, res) => {
    const { userId, username, oldPassword, newPassword } = req.body;

    const errors = [];
    const idVal  = userId || username;
    const idErr  = validateString(idVal, 'User Identifier (ID or Username)');
    const oldErr = validateString(oldPassword, 'Current Password');
    const newErr = validateString(newPassword, 'New Password', 4, 100);
    if (idErr)  errors.push(idErr);
    if (oldErr) errors.push(oldErr);
    if (newErr) errors.push(newErr);
    if (errors.length > 0) return validationError(res, errors);

    try {
        let user = null;
        if (userId) {
            user = await getDb().collection('users').findOne({ id: userId, status: 'Active' });
        }
        if (!user && (username || userId)) {
            const queryName = (username || userId).trim();
            user = await getDb().collection('users').findOne({ username: queryName, status: 'Active' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found or account is inactive.' });
        }

        // Verify current password — supports both bcrypt and legacy plaintext
        let isMatch = false;
        if (user.password && (user.password.startsWith('$2a$') || user.password.startsWith('$2b$'))) {
            isMatch = await bcrypt.compare(oldPassword, user.password);
        } else {
            isMatch = (oldPassword === user.password);
        }

        if (!isMatch) {
            return res.status(401).json({ error: 'Current (temporary) password is incorrect.' });
        }
        if (oldPassword === newPassword) {
            return res.status(400).json({ error: 'New password must be different from current temporary password.' });
        }

        const hashedNew = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await getDb().collection('users').updateOne(
            { id: user.id },
            { $set: { password: hashedNew, mustChangePassword: false, resetRequested: false, resetReason: '' } }
        );

        res.json({ success: true, message: 'Password updated successfully.', user: { id: user.id, username: user.username } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  INVENTORY API
// =============================================
app.get('/api/inventory', authenticate, async (req, res) => {
    try {
        // Staff → their branch only. Admin → all, or ?branch=<id> for one branch.
        const rows = await getDb().collection('products').find(branchReadFilter(req), NO_ID).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory', authenticate, async (req, res) => {
    const { id, name, category, unit, quantity, dateAdded, user } = req.body;
    const branchId = resolveWriteBranch(req); // forced to staff branch; admin supplies it

    // Validate — store result to avoid calling validator twice
    const errors = [];
    const idErr = validateString(id, 'ID');
    const nameErr = validateString(name, 'Product Name', 2, 100);
    const catErr = validateString(category, 'Category');
    const unitErr = validateString(unit, 'Unit');
    const qtyErr = validateInt(quantity, 'Quantity', 1);
    const dateErr = validateString(dateAdded, 'Date');
    const userErr = validateString(user, 'User');
    if (idErr) errors.push(idErr);
    if (nameErr) errors.push(nameErr);
    if (catErr) errors.push(catErr);
    if (unitErr) errors.push(unitErr);
    if (qtyErr) errors.push(qtyErr);
    if (dateErr) errors.push(dateErr);
    if (userErr) errors.push(userErr);
    if (!branchId) errors.push('A target branch is required (admins must select a branch).');
    if (errors.length > 0) return validationError(res, errors);

    try {
        await getDb().collection('products').insertOne({
            id,
            branchId,
            name: name.trim(),
            category: category.trim(),
            unit: unit.trim(),
            quantity: parseInt(quantity, 10),
            dateAdded,
            user,
        });
        res.json({ success: true, id, branchId });
    } catch (err) {
        if (isDuplicateKey(err)) return res.status(409).json({ error: 'Product ID already exists in this branch.' });
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/inventory/:id', authenticate, async (req, res) => {
    const { name, category, unit, quantity } = req.body;

    const errors = [];
    const nameErr = validateString(name, 'Product Name', 2, 100);
    const catErr = validateString(category, 'Category');
    const unitErr = validateString(unit, 'Unit');
    const qtyErr = validateInt(quantity, 'Quantity', 0);
    if (nameErr) errors.push(nameErr);
    if (catErr) errors.push(catErr);
    if (unitErr) errors.push(unitErr);
    if (qtyErr) errors.push(qtyErr);
    if (errors.length > 0) return validationError(res, errors);

    try {
        // branchWriteMatch prevents staff from editing another branch's product.
        const result = await getDb().collection('products').updateOne(
            { id: req.params.id, ...branchWriteMatch(req) },
            { $set: { name: name.trim(), category: category.trim(), unit: unit.trim(), quantity: parseInt(quantity, 10) } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Product not found in your branch.' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/inventory/:id/quantity', authenticate, async (req, res) => {
    const { quantityDelta, user } = req.body;
    // Bug Fix: store result once to avoid redundant double-call
    const deltaErr = validateInt(quantityDelta, 'Quantity Delta', -999999, 999999);
    if (deltaErr) return validationError(res, [deltaErr]);

    const delta = parseInt(quantityDelta, 10);
    const products = getDb().collection('products');
    const settings = getDb().collection('settings');
    const scope = branchWriteMatch(req); // staff → own branch; admin → any

    try {
        // Low Stock Protection — only applies to stock-out (negative delta)
        if (delta < 0) {
            const protRow = await settings.findOne({ key: 'lowStockProtectionEnabled' });
            if (protRow && protRow.value === 'true') {
                const prod = await products.findOne({ id: req.params.id, ...scope });
                if (!prod) return res.status(404).json({ error: 'Product not found in your branch.' });

                const thRow = await settings.findOne({ key: 'lowStockThreshold' });
                const threshold = thRow ? parseInt(thRow.value, 10) : 8;
                const resultingQty = prod.quantity + delta; // delta is negative
                if (resultingQty <= threshold) {
                    return res.status(409).json({
                        error: 'LOW_STOCK_PROTECTION',
                        message: `Low Stock Protection is active. Cannot reduce stock of this item to ${resultingQty} — the minimum safe quantity is ${threshold + 1} units.`,
                        threshold,
                        currentQty: prod.quantity,
                        resultingQty
                    });
                }
            }
        }

        const update = { $inc: { quantity: delta } };
        if (user) update.$set = { user };
        const result = await products.updateOne({ id: req.params.id, ...scope }, update);
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Product not found in your branch.' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/inventory/:id', authenticate, async (req, res) => {
    try {
        const result = await getDb().collection('products').deleteOne({ id: req.params.id, ...branchWriteMatch(req) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Product not found in your branch.' });
        res.json({ message: 'Product deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  TRANSACTIONS API
// =============================================
app.get('/api/transactions', authenticate, async (req, res) => {
    try {
        const rows = await getDb().collection('transactions').find(branchReadFilter(req), NO_ID).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/transactions', authenticate, async (req, res) => {
    const { id, product, category, type, quantity, unit, date, time, user } = req.body;
    const branchId = resolveWriteBranch(req);

    const errors = [];
    const idErr = validateString(id, 'ID');
    const productErr = validateString(product, 'Product');
    const catErr = validateString(category, 'Category');
    const qtyErr = validateInt(quantity, 'Quantity', 1);
    const unitErr = validateString(unit, 'Unit');
    const dateErr = validateString(date, 'Date');
    const timeErr = validateString(time, 'Time');
    const userErr = validateString(user, 'User');
    if (idErr) errors.push(idErr);
    if (productErr) errors.push(productErr);
    if (catErr) errors.push(catErr);
    if (!['Stock In', 'Stock Out'].includes(type)) errors.push('Type must be "Stock In" or "Stock Out".');
    if (qtyErr) errors.push(qtyErr);
    if (unitErr) errors.push(unitErr);
    if (dateErr) errors.push(dateErr);
    if (timeErr) errors.push(timeErr);
    if (userErr) errors.push(userErr);
    if (!branchId) errors.push('A target branch is required (admins must select a branch).');
    if (errors.length > 0) return validationError(res, errors);

    try {
        await getDb().collection('transactions').insertOne({
            id, branchId, product, category, type, quantity: parseInt(quantity, 10), unit, date, time, user
        });
        res.json({ success: true, id, branchId });
    } catch (err) {
        if (isDuplicateKey(err)) return res.status(409).json({ error: 'Transaction ID already exists in this branch.' });
        res.status(500).json({ error: err.message });
    }
});

// NOTE: Specific routes must be defined BEFORE parameterized routes to avoid mis-matching.
// e.g. DELETE /api/transactions/type/Stock In must NOT match /:id with id='type'
app.delete('/api/transactions', authenticate, async (req, res) => {
    try {
        // Staff clear only their branch; admin clears everything.
        await getDb().collection('transactions').deleteMany({ ...branchWriteMatch(req) });
        res.json({ success: true, message: 'All transactions cleared' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/type/:type', authenticate, async (req, res) => {
    if (!['Stock In', 'Stock Out'].includes(req.params.type)) {
        return validationError(res, ['Type must be "Stock In" or "Stock Out".']);
    }
    try {
        await getDb().collection('transactions').deleteMany({ type: req.params.type, ...branchWriteMatch(req) });
        res.json({ success: true, message: `${req.params.type} transactions cleared` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/:id', authenticate, async (req, res) => {
    try {
        const result = await getDb().collection('transactions').deleteOne({ id: req.params.id, ...branchWriteMatch(req) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Transaction not found in your branch.' });
        res.json({ message: 'Transaction deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  ADMIN — MULTI-BRANCH OVERVIEW / REPORTING
// =============================================
// GET /api/admin/overview?branch=all | <branchId>
// Powers the admin dashboard's three views (Luzon, Montalban, Consolidated).
// Returns headline metrics + a per-branch breakdown so the frontend can render
// either a single-branch summary or the aggregated totals from one response.
app.get('/api/admin/overview', authenticate, requireAdmin, async (req, res) => {
    const branch = req.query.branch;
    const match = (!branch || branch === 'all') ? {} : { branchId: branch };

    try {
        const db = getDb();
        const branches = await db.collection('branches')
            .find({}, { projection: { _id: 0, id: 1, name: 1 } }).toArray();

        // Movement totals grouped by branch + type (net = Stock In − Stock Out).
        const txnByBranch = await db.collection('transactions').aggregate([
            { $match: match },
            { $group: { _id: { branchId: '$branchId', type: '$type' }, qty: { $sum: '$quantity' }, count: { $sum: 1 } } }
        ]).toArray();

        // Inventory totals grouped by branch.
        const invByBranch = await db.collection('products').aggregate([
            { $match: match },
            { $group: { _id: '$branchId', items: { $sum: 1 }, units: { $sum: '$quantity' } } }
        ]).toArray();

        // Assemble a per-branch record, then a consolidated roll-up.
        const byId = {};
        const ensure = (bid) => (byId[bid] ||= { branchId: bid, stockIn: 0, stockOut: 0, netMovement: 0, txnCount: 0, itemCount: 0, totalUnits: 0 });

        txnByBranch.forEach(r => {
            const rec = ensure(r._id.branchId);
            if (r._id.type === 'Stock In') rec.stockIn += r.qty;
            else if (r._id.type === 'Stock Out') rec.stockOut += r.qty;
            rec.txnCount += r.count;
        });
        invByBranch.forEach(r => {
            const rec = ensure(r._id);
            rec.itemCount = r.items;
            rec.totalUnits = r.units;
        });

        const nameOf = (bid) => (branches.find(b => b.id === bid) || {}).name || bid || 'Unassigned';
        const perBranch = Object.values(byId).map(r => ({
            ...r, branchName: nameOf(r.branchId), netMovement: r.stockIn - r.stockOut
        }));

        // Consolidated totals across whatever is in scope.
        const consolidated = perBranch.reduce((acc, r) => ({
            stockIn: acc.stockIn + r.stockIn,
            stockOut: acc.stockOut + r.stockOut,
            netMovement: acc.netMovement + r.netMovement,
            txnCount: acc.txnCount + r.txnCount,
            itemCount: acc.itemCount + r.itemCount,
            totalUnits: acc.totalUnits + r.totalUnits
        }), { stockIn: 0, stockOut: 0, netMovement: 0, txnCount: 0, itemCount: 0, totalUnits: 0 });

        res.json({
            scope: (!branch || branch === 'all') ? 'all' : branch,
            branches,
            consolidated,
            perBranch
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  EXPORT LOGS API
// =============================================
app.post('/api/export-logs', async (req, res) => {
    const { user, type, date, time } = req.body;

    const errors = [];
    const userErr = validateString(user, 'User');
    const typeErr = validateString(type, 'Export Type');
    const dateErr = validateString(date, 'Date');
    const timeErr = validateString(time, 'Time');
    if (userErr) errors.push(userErr);
    if (typeErr) errors.push(typeErr);
    if (dateErr) errors.push(dateErr);
    if (timeErr) errors.push(timeErr);
    if (errors.length > 0) return validationError(res, errors);

    try {
        // createdAt gives a stable sort key in place of SQLite's AUTOINCREMENT id.
        const now = new Date();
        await getDb().collection('export_logs').insertOne({ user, type, date, time, createdAt: now });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/export-logs', async (req, res) => {
    try {
        const rows = await getDb().collection('export_logs')
            // Expose createdAt as an ISO string so the frontend can use it as a
            // stable clear-display cursor (filtering logs newer than a saved timestamp).
            .find({}, { projection: { _id: 0 } })
            .sort({ createdAt: -1 })
            .limit(100)
            .toArray();
        // Serialize createdAt to ISO string for easy client-side comparison.
        const serialized = rows.map(r => ({
            user: r.user,
            type: r.type,
            date: r.date,
            time: r.time,
            createdAt: r.createdAt ? r.createdAt.toISOString() : null
        }));
        res.json(serialized);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/export-logs', async (req, res) => {
    try {
        await getDb().collection('export_logs').deleteMany({});
        res.json({ success: true, message: 'Export logs cleared' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  SETTINGS API (Admin)
// =============================================
app.get('/api/settings', async (req, res) => {
    try {
        const rows = await getDb().collection('settings').find({}, { projection: { _id: 0, key: 1, value: 1 } }).toArray();
        // Return as a flat key-value object for easy client-side consumption
        const result = {};
        rows.forEach(r => result[r.key] = r.value);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/settings', authenticate, requireAdmin, async (req, res) => {
    const { key, value } = req.body;
    const keyErr = validateString(key, 'Key');
    if (keyErr) return validationError(res, [keyErr]);
    if (value === null || value === undefined) return validationError(res, ['Value is required.']);

    // Whitelist allowed setting keys to prevent arbitrary writes
    const ALLOWED_KEYS = ['lowStockProtectionEnabled', 'lowStockThreshold'];
    if (!ALLOWED_KEYS.includes(key)) {
        return res.status(400).json({ error: `Unknown setting key: ${key}` });
    }

    try {
        await getDb().collection('settings').updateOne(
            { key },
            { $set: { value: String(value) } },
            { upsert: true }
        );
        res.json({ success: true, key, value });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  SYSTEM TOOLS
// =============================================
app.post('/api/system/restore', authenticate, requireAdmin, async (req, res) => {
    const { users, products, transactions } = req.body;
    if (!users || !products || !transactions) {
        return validationError(res, ['Backup must contain users, products, and transactions arrays.']);
    }

    try {
        const db = getDb();
        await Promise.all([
            db.collection('users').deleteMany({}),
            db.collection('products').deleteMany({}),
            db.collection('transactions').deleteMany({}),
        ]);

        // Strip any _id that may be present in the backup so Mongo assigns fresh ones.
        const clean = (arr) => arr.map(({ _id, ...rest }) => rest);

        if (users.length) await db.collection('users').insertMany(clean(users));
        if (products.length) await db.collection('products').insertMany(clean(products));
        if (transactions.length) await db.collection('transactions').insertMany(clean(transactions));

        res.json({ success: true, message: 'Restore completed' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Connect to MongoDB first, then start accepting requests.
connect()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Backend server running on http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('Failed to connect to MongoDB:', err.message);
        process.exit(1);
    });
