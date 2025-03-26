const bcrypt = require('bcrypt');

const adminUsers = {
    "admin@empresa.com": {
        password: "", // Will be hashed
        resetToken: null,
        resetTokenExpiry: null
    },
    "otroadmin@empresa.com": {
        password: "", // Will be hashed
        resetToken: null,
        resetTokenExpiry: null
    }
};

// Initialize admin passwords
async function initializeAdminPasswords() {
    for (const email in adminUsers) {
        adminUsers[email].password = await bcrypt.hash("1234", 10);
    }
}

module.exports = { adminUsers, initializeAdminPasswords };