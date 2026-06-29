const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { connect, getDb } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Allow only our frontend origin(s). Set FRONTEND_ORIGIN in Render to the
// static site's URL (e.g. https://bhandol-frontend.onrender.com).
// Comma-separate to allow several (e.g. include http://localhost:3000 for dev).
const allowedOrigins = ("https://bhandol-backend.onrender.com" || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin/non-browser requests (no Origin header) and any
    // explicitly allow-listed frontend origin.
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error(`Origin ${origin} not allowed by CORS`));
  },
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
//  USERS API
// =============================================
app.get('/api/users', async (req, res) => {
    try {
        // SECURITY OVERRIDE: User explicitly requested passwords be viewable in Admin portal.
        const rows = await getDb().collection('users')
            .find({}, { projection: { _id: 0, id: 1, name: 1, username: 1, password: 1, role: 1, status: 1 } })
            .toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', async (req, res) => {
    const { id, name, username, password, role, status } = req.body;

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
    if (errors.length > 0) return validationError(res, errors);

    try {
        // SECURITY OVERRIDE: User explicitly requested plaintext passwords.
        await getDb().collection('users').insertOne({ id, name, username, password, role, status });
        res.json({ id, name, username, role, status });
    } catch (err) {
        if (isDuplicateKey(err)) {
            return res.status(409).json({ error: 'Username already exists.' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/:id/status', async (req, res) => {
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

app.delete('/api/users/:id', async (req, res) => {
    try {
        await getDb().collection('users').deleteOne({ id: req.params.id });
        res.json({ message: 'User deleted' });
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
            res.json({ success: true, user: { id: row.id, name: row.name, username: row.username, role: row.role } });
        } else {
            failDelay(() => res.status(401).json({ success: false, message: 'Invalid credentials or inactive account' }));
        }
    } catch (err) {
        failDelay(() => res.status(500).json({ error: 'Authentication error.' }));
    }
});

// =============================================
//  INVENTORY API
// =============================================
app.get('/api/inventory', async (req, res) => {
    try {
        const rows = await getDb().collection('products').find({}, NO_ID).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory', async (req, res) => {
    const { id, name, category, unit, quantity, dateAdded, user } = req.body;

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
    if (errors.length > 0) return validationError(res, errors);

    try {
        await getDb().collection('products').insertOne({
            id,
            name: name.trim(),
            category: category.trim(),
            unit: unit.trim(),
            quantity: parseInt(quantity, 10),
            dateAdded,
            user,
        });
        res.json({ success: true, id });
    } catch (err) {
        if (isDuplicateKey(err)) return res.status(409).json({ error: 'Product ID already exists.' });
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/inventory/:id', async (req, res) => {
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
        await getDb().collection('products').updateOne(
            { id: req.params.id },
            { $set: { name: name.trim(), category: category.trim(), unit: unit.trim(), quantity: parseInt(quantity, 10) } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/inventory/:id/quantity', async (req, res) => {
    const { quantityDelta, user } = req.body;
    // Bug Fix: store result once to avoid redundant double-call
    const deltaErr = validateInt(quantityDelta, 'Quantity Delta', -999999, 999999);
    if (deltaErr) return validationError(res, [deltaErr]);

    const delta = parseInt(quantityDelta, 10);
    const products = getDb().collection('products');
    const settings = getDb().collection('settings');

    try {
        // Low Stock Protection — only applies to stock-out (negative delta)
        if (delta < 0) {
            const protRow = await settings.findOne({ key: 'lowStockProtectionEnabled' });
            if (protRow && protRow.value === 'true') {
                const prod = await products.findOne({ id: req.params.id });
                if (!prod) return res.status(500).json({ error: 'Product not found.' });

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
        await products.updateOne({ id: req.params.id }, update);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/inventory/:id', async (req, res) => {
    try {
        await getDb().collection('products').deleteOne({ id: req.params.id });
        res.json({ message: 'Product deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
//  TRANSACTIONS API
// =============================================
app.get('/api/transactions', async (req, res) => {
    try {
        const rows = await getDb().collection('transactions').find({}, NO_ID).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/transactions', async (req, res) => {
    const { id, product, category, type, quantity, unit, date, time, user } = req.body;

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
    if (errors.length > 0) return validationError(res, errors);

    try {
        await getDb().collection('transactions').insertOne({
            id, product, category, type, quantity: parseInt(quantity, 10), unit, date, time, user
        });
        res.json({ success: true, id });
    } catch (err) {
        if (isDuplicateKey(err)) return res.status(409).json({ error: 'Transaction ID already exists.' });
        res.status(500).json({ error: err.message });
    }
});

// NOTE: Specific routes must be defined BEFORE parameterized routes to avoid mis-matching.
// e.g. DELETE /api/transactions/type/Stock In must NOT match /:id with id='type'
app.delete('/api/transactions', async (req, res) => {
    try {
        await getDb().collection('transactions').deleteMany({});
        res.json({ success: true, message: 'All transactions cleared' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/type/:type', async (req, res) => {
    if (!['Stock In', 'Stock Out'].includes(req.params.type)) {
        return validationError(res, ['Type must be "Stock In" or "Stock Out".']);
    }
    try {
        await getDb().collection('transactions').deleteMany({ type: req.params.type });
        res.json({ success: true, message: `${req.params.type} transactions cleared` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/:id', async (req, res) => {
    try {
        await getDb().collection('transactions').deleteOne({ id: req.params.id });
        res.json({ message: 'Transaction deleted' });
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
    if (validateString(user, 'User')) errors.push(validateString(user, 'User'));
    if (validateString(type, 'Export Type')) errors.push(validateString(type, 'Export Type'));
    if (validateString(date, 'Date')) errors.push(validateString(date, 'Date'));
    if (validateString(time, 'Time')) errors.push(validateString(time, 'Time'));
    if (errors.length > 0) return validationError(res, errors);

    try {
        // createdAt gives a stable sort key in place of SQLite's AUTOINCREMENT id.
        const result = await getDb().collection('export_logs').insertOne({ user, type, date, time, createdAt: new Date() });
        res.json({ success: true, id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/export-logs', async (req, res) => {
    try {
        const rows = await getDb().collection('export_logs')
            .find({}, { projection: { _id: 0, createdAt: 0 } })
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray();
        res.json(rows);
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

app.post('/api/settings', async (req, res) => {
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
app.post('/api/system/restore', async (req, res) => {
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
