const { connect, client } = require('./database');

async function seed() {
    const db = await connect();

    // ── Branches (tenant registry) ──────────────────────────────────
    const branches = [
        { id: "BR-LUZ", code: "LUZ", name: "Luzon",     status: "Active" },
        { id: "BR-MON", code: "MON", name: "Montalban", status: "Active" }
    ];
    for (const b of branches) {
        await db.collection('branches').updateOne({ id: b.id }, { $set: b }, { upsert: true });
    }

    // ── Users ───────────────────────────────────────────────────────
    // Admins are branch-agnostic (branchId: null = all branches).
    // Staff MUST be tied to exactly one branch.
    const defaultUsers = [
        { id: "USR01", name: "Herrera, Christopher John", username: "admin", password: "admin123", role: "admin", status: "Active", branchId: null },
        { id: "USR02", name: "Teresita, Tragura",         username: "staff", password: "staff123", role: "staff", status: "Active", branchId: "BR-MON" }
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
