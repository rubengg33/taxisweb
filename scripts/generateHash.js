const bcrypt = require('bcryptjs');

async function generateHash() {
    const password = "Wetaxiadmins2025"; // Contraseña que quieras
    const hash = await bcrypt.hash(password, 10);
    console.log('Hashed password:', hash);
}

generateHash();