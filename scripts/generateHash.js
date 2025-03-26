const bcrypt = require('bcryptjs');

async function generateHash() {
    const password = "Wetaxiadmins2025"; // Your desired initial password
    const hash = await bcrypt.hash(password, 10);
    console.log('Hashed password:', hash);
}

generateHash();