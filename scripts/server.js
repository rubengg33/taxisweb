const express = require("express");
const mysql = require("mysql2");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // Add this line
require("dotenv").config();
const cors = require("cors");
const { sendPasswordResetEmail } = require('../utils/emailService');

// Add the middleware functions
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ message: 'Invalid API Key' });
    }
    next();
};

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection(process.env.DATABASE_URL);

db.connect(err => {
    if (err) {
        console.error("Error conectando a MySQL:", err);
        return;
    }
    console.log("Conectado a MySQL 🚀");
});

const admins = {
    "admin@empresa.com": "1234",
    "otroadmin@empresa.com": "1234"
};
//

app.get("/", (req, res) => {
    res.send("¡El servidor está funcionando correctamente!");
});

// Backend (Node.js)
app.get("/api/config", (req, res) => {
    res.json({ apiUrl: process.env.API_URL });
});


// Obtener todos los titulares (licencias)
app.get("/api/licencias", authenticateToken, validateApiKey, (req, res) => {
    db.query("SELECT * FROM licencias", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});
//Crear titular
app.post("/api/licencias", (req, res) => {
    console.log("📩 Datos recibidos en el servidor:", req.body); // Para verificar los datos enviados

    const { licencia, dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal } = req.body;

    if (!licencia || !dni || !nombre_apellidos || !matricula || !marca_modelo || !email || !numero_patronal) {
        return res.status(400).json({ message: "Faltan campos obligatorios." });
    }

    const sql = "INSERT INTO licencias (licencia, dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal) VALUES (?, ?, ?, ?, ?, ?, ?)";
    db.query(sql, [licencia, dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal], (err, result) => {
        if (err) {
            console.error("❌ Error en la consulta SQL:", err);
            return res.status(500).json({ message: "Error en la base de datos", error: err.sqlMessage });
        }
        console.log("✅ Licencia insertada:", result);
        res.json({ message: "Titular agregado exitosamente" });
    }); 
});


// Obtener una licencia por su número
app.get("/api/licencias/:licencia", (req, res) => {
    const licencia = req.params.licencia;
    db.query("SELECT * FROM licencias WHERE LICENCIA = ?", [licencia], (err, result) => {
        if (err) return res.status(500).json({ error: "Error en el servidor" });
        if (result.length === 0) return res.status(404).json({ error: "Licencia no encontrada" });
        res.json(result[0]);
    });
});

// Actualizar un titular por licencia
app.put("/api/licencias/:licencia", (req, res) => {
    const oldLicencia = req.params.licencia;
    const { licencia, dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal } = req.body;

    const query = `
        UPDATE licencias 
        SET licencia = ?, dni = ?, nombre_apellidos = ?, matricula = ?, marca_modelo = ?, 
            email = ?, numero_patronal = ? 
        WHERE licencia = ?
    `;

    db.query(query, [
        licencia || oldLicencia, // Use new license if provided, otherwise keep the old one
        dni, 
        nombre_apellidos, 
        matricula, 
        marca_modelo, 
        email, 
        numero_patronal, 
        oldLicencia
    ], (err, result) => {
        if (err) return res.status(500).json({ error: "Error al actualizar titular", details: err.sqlMessage });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Titular no encontrado" });
        res.json({ message: "Titular actualizado correctamente" });
    });
});

// Eliminar una licencia por su ID
app.delete("/api/licencias/:licencia", (req, res) => {
    const licencia = req.params.licencia;
    db.query("DELETE FROM licencias WHERE LICENCIA = ?", [licencia], (err, result) => {
        if (err) return res.status(500).json({ error: "Error eliminando la licencia" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Licencia no encontrada" });
        res.json({ message: "Licencia eliminada correctamente" });
    });
});
// Obtener todos los conductores
app.get("/api/conductores", authenticateToken, validateApiKey, (req, res) => {
    db.query("SELECT * FROM conductores", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// También proteger las demás rutas de conductores
app.get("/api/conductores/:id", authenticateToken, validateApiKey, (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM conductores WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error obteniendo conductor" });
        if (result.length === 0) return res.status(404).json({ error: "Conductor no encontrado" });
        res.json(result[0]);
    });
});

// Añadir este nuevo endpoint para verificar licencia
app.get("/api/conductores/check-licencia/:licencia", authenticateToken, validateApiKey, (req, res) => {
    const licencia = req.params.licencia;
    db.query("SELECT COUNT(*) as count FROM conductores WHERE licencia = ?", [licencia], (err, result) => {
        if (err) return res.status(500).json({ error: "Error verificando licencia" });
        res.json({ exists: result[0].count > 0 });
    });
});

// Modificar el endpoint de crear conductor
app.post("/api/conductores", authenticateToken, validateApiKey, (req, res) => {
    console.log("📩 Datos recibidos en el servidor:", req.body);

    const { nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia } = req.body;

    if (!nombre_apellidos || !dni || !direccion || !codigo_postal || !email || !numero_seguridad_social || !licencia) {
        return res.status(400).json({ message: "Faltan campos obligatorios." });
    }

    // Primero verificar si la licencia ya está en uso
    db.query("SELECT COUNT(*) as count FROM conductores WHERE licencia = ?", [licencia], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Error verificando licencia", error: err.sqlMessage });
        }

        if (result[0].count > 0) {
            return res.status(409).json({ message: "Esta licencia ya está asignada a otro conductor." });
        }

        // Si la licencia no está en uso, proceder con la inserción
        const sql = "INSERT INTO conductores (nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia) VALUES (?, ?, ?, ?, ?, ?, ?)";
        db.query(sql, [nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia], (err, result) => {
            if (err) {
                console.error("❌ Error en la consulta SQL:", err);
                return res.status(500).json({ message: "Error en la base de datos", error: err.sqlMessage });
            }
            console.log("✅ Conductor insertado:", result);
            res.json({ message: "Conductor agregado exitosamente" });
        });
    });
});

// Actualizar un conductor por ID
app.put("/api/conductores/:id", (req, res) => {
    const id = req.params.id;
    const { nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia } = req.body;
    const query = "UPDATE conductores SET nombre_apellidos = ?, dni = ?, direccion = ?, codigo_postal = ?, email = ?, numero_seguridad_social = ?, licencia = ? WHERE id = ?";
    db.query(query, [nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia, id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error al actualizar conductor" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Conductor no encontrado" });
        res.json({ message: "Conductor actualizado correctamente" });
    });
});

// Eliminar un conductor por ID
app.delete("/api/conductores/:id", (req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM conductores WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error eliminando el conductor" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Conductor no encontrado" });
        res.json({ message: "Conductor eliminado correctamente" });
    });
});
// Endpoint para cerrar sesión
app.post("/api/logout", (req, res) => {
    res.json({ message: "Sesión cerrada correctamente" });
});
const PORT = process.env.PORT;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT} 🚀`);
});

// Búsqueda en todos los campos de licencias
app.get("/api/licencias/buscar/:termino", authenticateToken, validateApiKey, (req, res) => {
    const termino = req.params.termino;
    const query = `SELECT * FROM licencias WHERE 
        LICENCIA LIKE ? OR 
        DNI LIKE ? OR 
        NOMBRE_APELLIDOS LIKE ? OR 
        MATRICULA LIKE ? OR 
        MARCA_MODELO LIKE ? OR 
        EMAIL LIKE ? OR 
        NUMERO_PATRONAL LIKE ?`;
    const searchTerm = `%${termino}%`;
    db.query(query, Array(7).fill(searchTerm), (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// Búsqueda en todos los campos de conductores
app.get("/api/conductores/buscar/:termino", authenticateToken, validateApiKey, (req, res) => {
    const termino = req.params.termino;
    const query = `SELECT * FROM conductores WHERE 
        id LIKE ? OR 
        nombre_apellidos LIKE ? OR 
        dni LIKE ? OR 
        direccion LIKE ? OR 
        codigo_postal LIKE ? OR 
        email LIKE ? OR 
        numero_seguridad_social LIKE ? OR 
        licencia LIKE ?`;
    const searchTerm = `%${termino}%`;
    db.query(query, Array(8).fill(searchTerm), (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});


// Modified login endpoint
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    // Check if admin
    const [admins] = await db.promise().query('SELECT * FROM admins WHERE email = ?', [email]);
    if (admins.length > 0) {
        const isValidPassword = await bcrypt.compare(password, admins[0].password);
        if (isValidPassword) {
            const token = jwt.sign({ email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '24h' });
            return res.json({ exists: true, admin: true, token });
        }
    }
      return res.json({ exists: false });
});

// Login endpoint for empresa
app.post("/api/login-empresa", async (req, res) => {
    const { email, dni } = req.body;

    try {
        // Check if the email and DNI exist in licencias table
        const query = "SELECT * FROM licencias WHERE EMAIL = ? AND DNI = ?";
        db.query(query, [email, dni], (err, result) => {
            if (err) {
                console.error("Error en la consulta:", err);
                return res.status(500).json({ error: "Error en el servidor" });
            }
            
            if (result.length > 0) {
                // Create JWT token for empresa
                const token = jwt.sign(
                    { 
                        email, 
                        isEmpresa: true,
                        licencia: result[0].LICENCIA 
                    }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '24h' }
                );

                return res.json({ 
                    exists: true,
                    token,
                    empresaData: {
                        nombre: result[0].NOMBRE_APELLIDOS,
                        licencia: result[0].LICENCIA,
                        matricula: result[0].MATRICULA,
                        marca_modelo: result[0].MARCA_MODELO
                    }
                });
            } else {
                return res.json({ exists: false });
            }
        });
    } catch (error) {
        console.error("Error en login-empresa:", error);
        return res.status(500).json({ error: "Error en el servidor" });
    }
});

// Password reset request endpoint
app.post("/api/request-password-reset", async (req, res) => {
    const { email } = req.body;
    
    const [admins] = await db.promise().query('SELECT * FROM admins WHERE email = ?', [email]);
    if (admins.length === 0) {
        return res.status(404).json({ message: "Email no encontrado" });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = Date.now() + 3600000; // 1 hour

    // Store token in database
    await db.promise().query(
        'UPDATE admins SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?',
        [resetToken, tokenExpiry, email]
    );

    try {
        await sendPasswordResetEmail(email, resetToken);
        res.json({ message: "Email de recuperación enviado" });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: "Error al enviar el email" });
    }
});

// Password reset endpoint
app.post("/api/reset-password", async (req, res) => {
    const { email, token, newPassword } = req.body;

    const [admins] = await db.promise().query(
        'SELECT * FROM admins WHERE email = ? AND resetToken = ?',
        [email, token]
    );

    if (admins.length === 0) {
        return res.status(400).json({ message: "Token inválido" });
    }

    const admin = admins[0];
    if (!admin.resetToken || admin.resetTokenExpiry < Date.now()) {
        return res.status(400).json({ message: "Token expirado" });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.promise().query(
            'UPDATE admins SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE email = ?',
            [hashedPassword, email]
        );

        res.json({ message: "Contraseña actualizada correctamente" });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: "Error al actualizar la contraseña" });
    }
});