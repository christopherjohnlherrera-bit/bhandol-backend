// One-time backfill: assign a branchId to legacy products, transactions and
// staff users created BEFORE the multi-branch upgrade (documents where
// branchId is missing or null).
//
//   node backfill-branch.js            → assigns to BR-MON (Montalban) by default
//   node backfill-branch.js BR-LUZ     → assigns legacy rows to Luzon instead
//
// Admins are intentionally left with branchId: null (all branches).
// Run once after `npm run seed` (which creates the branches).

const { connect, client } = require('./database');

async function backfill() {
    const targetBranch = (process.argv[2] || 'BR-MON').trim();
    const db = await connect();

    const branch = await db.collection('branches').findOne({ id: targetBranch });
    if (!branch) {
        console.error(`❌ Branch "${targetBranch}" not found. Run "npm run seed" first, or pass a valid branch id.`);
        await client.close();
        process.exit(1);
    }

    const missing = { $or: [{ branchId: { $exists: false } }, { branchId: null }] };

    const prod = await db.collection('products').updateMany(missing, { $set: { branchId: targetBranch } });
    const txn  = await db.collection('transactions').updateMany(missing, { $set: { branchId: targetBranch } });
    // Only staff get a branch; admins stay branch-agnostic.
    const staff = await db.collection('users').updateMany(
        { role: 'staff', ...missing },
        { $set: { branchId: targetBranch } }
    );

    console.log(`✓ products:     ${prod.modifiedCount} assigned to ${branch.name}`);
    console.log(`✓ transactions: ${txn.modifiedCount} assigned to ${branch.name}`);
    console.log(`✓ staff users:  ${staff.modifiedCount} assigned to ${branch.name}`);
    console.log('\n✅ Backfill complete.');

    await client.close();
    process.exit(0);
}

backfill().catch(err => {
    console.error('❌ Backfill failed:', err.message);
    process.exit(1);
});
