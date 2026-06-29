// One-time migration: copies all data from the existing SQLite bhandol.db
// into MongoDB. Run this ONCE, after `npm install` and before removing sqlite3.
//
//   node migrate-to-mongo.js
//
// Safe to run on an empty Mongo database. Existing collections are cleared
// first so the migration is idempotent (re-running gives the same result).

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { connect, client } = require('./database');

const dbPath = path.resolve(__dirname, 'bhandol.db');

// Promisified helper for sqlite3 SELECT *.
function readTable(sqlite, table) {
    return new Promise((resolve, reject) => {
        sqlite.all(`SELECT * FROM ${table}`, [], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

async function migrate() {
    const sqlite = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY);
    const mongo = await connect();

    const tables = ['users', 'products', 'transactions', 'export_logs', 'settings'];

    for (const table of tables) {
        let rows;
        try {
            rows = await readTable(sqlite, table);
        } catch (err) {
            console.log(`⚠️  Skipping "${table}" (${err.message})`);
            continue;
        }

        const col = mongo.collection(table);
        await col.deleteMany({});

        if (rows.length === 0) {
            console.log(`• ${table}: 0 rows (empty)`);
            continue;
        }

        // export_logs had an AUTOINCREMENT integer id in SQLite; convert it to a
        // createdAt timestamp so ordering is preserved without colliding with _id.
        if (table === 'export_logs') {
            rows = rows.map(r => {
                const { id, ...rest } = r;
                return { ...rest, createdAt: new Date(Date.now() + id) };
            });
        }

        await col.insertMany(rows);
        console.log(`✓ ${table}: migrated ${rows.length} rows`);
    }

    sqlite.close();
    await client.close();
    console.log('\n✅ Migration complete.');
    process.exit(0);
}

migrate().catch(err => {
    console.error('❌ Migration failed:', err.message);
    process.exit(1);
});
