const { connect, client } = require('./database');

async function seed() {
    const db = await connect();

    const defaultUsers = [
        { id: "USR01", name: "Herrera, Christopher John", username: "admin", password: "admin123", role: "admin", status: "Active" },
        { id: "USR02", name: "Teresita, Tragura", username: "staff", password: "staff123", role: "staff", status: "Active" }
    ];

    // Upsert by username so re-running the seed doesn't throw on the unique index.
    for (const u of defaultUsers) {
        await db.collection('users').updateOne(
            { username: u.username },
            { $set: u },
            { upsert: true }
        );
    }

    console.log("Database seeded successfully.");
    await client.close();
}

seed().catch(err => {
    console.error("Seed failed:", err.message);
    process.exit(1);
});
