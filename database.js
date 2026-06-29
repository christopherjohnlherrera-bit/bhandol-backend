const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGO_URI;
const dbName = process.env.MONGO_DB || 'bhandol';

if (!uri) {
  console.error('FATAL: MONGO_URI is not set. Create a server/.env file with your MongoDB Atlas connection string.');
  process.exit(1);
}

const client = new MongoClient(uri);
let db = null;

// Connect once at startup and create the indexes that replace SQLite's
// PRIMARY KEY / UNIQUE constraints.
async function connect() {
  if (db) return db;
  await client.connect();
  db = client.db(dbName);

  await Promise.all([
    db.collection('users').createIndex({ id: 1 }, { unique: true }),
    db.collection('users').createIndex({ username: 1 }, { unique: true }),
    db.collection('products').createIndex({ id: 1 }, { unique: true }),
    db.collection('transactions').createIndex({ id: 1 }, { unique: true }),
    db.collection('settings').createIndex({ key: 1 }, { unique: true }),
  ]);

  console.log(`Connected to the MongoDB database: ${dbName}`);
  return db;
}

// Throws if connect() hasn't run yet — keeps routes from silently hitting a null db.
function getDb() {
  if (!db) throw new Error('Database not connected. Call connect() first.');
  return db;
}

module.exports = { connect, getDb, client };
