const bcrypt = require('bcryptjs');
const { connect, client } = require('./database');

// Parse CLI arguments
const args = process.argv.slice(2);

if (args.length !== 2) {
    console.log('----------------------------------------------------');
    console.log('❌ ERROR: Invalid arguments.');
    console.log('USAGE: node reset-admin.js <username> <new_password>');
    console.log('EXAMPLE: node reset-admin.js admin "MyNewPass123!"');
    console.log('----------------------------------------------------');
    process.exit(1);
}

const targetUsername = args[0].trim();
const newPassword = args[1].trim();

if (newPassword.length < 4) {
    console.log('❌ ERROR: Password must be at least 4 characters long.');
    process.exit(1);
}

async function resetAdmin() {
    const db = await connect();

    console.log(`\n🔍 Searching for user: "${targetUsername}"...`);

    const user = await db.collection('users').findOne({ username: targetUsername }, { projection: { id: 1, role: 1 } });

    if (!user) {
        console.log(`❌ ERROR: User "${targetUsername}" not found in the database.`);
        await client.close();
        process.exit(1);
    }

    if (user.role !== 'admin') {
        console.log(`⚠️ WARNING: User "${targetUsername}" is a STAFF member, not an ADMIN.`);
        console.log('Proceeding with password reset anyway...');
    }

    console.log('🔐 Hashing new password securely...');
    const SALT_ROUNDS = 10;
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    await db.collection('users').updateOne({ id: user.id }, { $set: { password: hashedPassword } });

    console.log('----------------------------------------------------');
    console.log(`✅ SUCCESS! Password for "${targetUsername}" has been reset.`);
    console.log(`You can now log in at the main screen using the new password.`);
    console.log('----------------------------------------------------\n');

    await client.close();
    process.exit(0);
}

resetAdmin().catch(err => {
    console.error('❌ ERROR:', err.message);
    process.exit(1);
});
