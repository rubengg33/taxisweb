const express = require("express");
const mysql = require("mysql2");
require("dotenv").config();
const cors = require("cors");

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


app.get("/", (req, res) => {
    res.send("¡El servidor está funcionando correctamente!");
});

app.get("/config", (req, res) => {
    console.log("API_URL en el servidor:", process.env.API_URL); // Verifica que la variable está disponible
    if (!process.env.API_URL) {
        return res.status(500).json({ error: "API_URL no está definida en el archivo .env" });
    }
    res.json({ apiUrl: process.env.API_URL });
});
// Endpoint para iniciar sesión
app.post("/api/login", (req, res) => {
    const { email, dni } = req.body;

    // Verificar si es un admin (SIN base de datos)
    if (admins[email] && admins[email] === dni) {
        return res.json({ exists: true, admin: true });
    }

    // Si no es admin, verificar en la base de datos
    const query = "SELECT * FROM conductores WHERE EMAIL = ? AND DNI = ?";
    db.query(query, [email, dni], (err, result) => {
        if (err) return res.status(500).json({ error: "Error en el servidor" });
        
        if (result.length > 0) {
            return res.json({ exists: true, admin: false }); // Usuario normal
        } else {
            return res.json({ exists: false });
        }
    });
});
// Obtener todos los titulares (licencias)
app.get("/api/licencias", (req, res) => {
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
    const licencia = req.params.licencia;
    const { dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal } = req.body;

    const query = `
        UPDATE licencias 
        SET dni = ?, nombre_apellidos = ?, matricula = ?, marca_modelo = ?, email = ?, numero_patronal = ? 
        WHERE licencia = ?
    `;

    db.query(query, [dni, nombre_apellidos, matricula, marca_modelo, email, numero_patronal, licencia], (err, result) => {
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
app.get("/api/conductores", (req, res) => {
    db.query("SELECT * FROM conductores", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});
//obtener conductor por id
app.get("/api/conductores/:id", (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM conductores WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error obteniendo conductor" });
        if (result.length === 0) return res.status(404).json({ error: "Conductor no encontrado" });
        res.json(result[0]);
    });
});

// Añadir este nuevo endpoint para verificar licencia
app.get("/api/conductores/check-licencia/:licencia", (req, res) => {
    const licencia = req.params.licencia;
    db.query("SELECT COUNT(*) as count FROM conductores WHERE licencia = ?", [licencia], (err, result) => {
        if (err) return res.status(500).json({ error: "Error verificando licencia" });
        res.json({ exists: result[0].count > 0 });
    });
});

// Modificar el endpoint de crear conductor
app.post("/api/conductores", (req, res) => {
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
app.get("/api/licencias/buscar/:termino", (req, res) => {
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
app.get("/api/conductores/buscar/:termino", (req, res) => {
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