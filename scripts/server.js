const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Ovejita123",
    database: "controlconductores",
    port: 3306
});

db.connect(err => {
    if (err) {
        console.error("Error conectando a MySQL:", err);
        return;
    }
    console.log("Conectado a MySQL 🚀");
});

// Endpoint para iniciar sesión
app.post("/api/login", (req, res) => {
    const { email, dni } = req.body;
    const query = "SELECT * FROM conductores WHERE EMAIL = ? AND DNI = ?";
    db.query(query, [email, dni], (err, result) => {
        if (err) return res.status(500).json({ error: "Error en el servidor" });
        res.json({ exists: result.length > 0 });
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

app.get("/api/conductores/:id", (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM conductores WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error obteniendo conductor" });
        if (result.length === 0) return res.status(404).json({ error: "Conductor no encontrado" });
        res.json(result[0]);
    });
});

// Crear conductor
app.post("/api/conductores", (req, res) => {
    console.log("📩 Datos recibidos en el servidor:", req.body); // Ver qué datos llegan al servidor

    const { nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia } = req.body;

    if (!nombre_apellidos || !dni || !direccion || !codigo_postal || !email || !numero_seguridad_social || !licencia) {
        return res.status(400).json({ message: "Faltan campos obligatorios." });
    }

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

app.listen(3000, () => {
    console.log("Servidor ejecutándose en http://localhost:3000 🚀");
});