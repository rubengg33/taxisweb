const express = require("express");
const mysql = require("mysql2");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // Add this line
require("dotenv").config();
const cors = require("cors");
const { DateTime } = require("luxon");
const nodemailer = require('nodemailer');
const { sendPasswordResetEmail } = require('../utils/emailService');
const multer = require('multer'); 
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const schedule = require('node-schedule');
// Add the middleware functions
// Configura tu transporter de nodemailer (SMTP o servicio)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: 'controldeconductores@wetaximadrid.com',
      pass: 'lsqz yyta xlwo hpms'
    }
  });
  
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
//
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ message: 'Invalid API Key' });
    }
    next();
};
const app = express();
const upload = multer({ dest: path.join(__dirname, 'uploads/') });


// Configuración de CORS
const corsOptions = {
    origin: process.env.FRONTEND_URL, // Esto usará 'https://controldeconductores.com'
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
    credentials: true
  };
  
  // Aplicar CORS como middleware
  app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

const conductorCache = new Map();
const db = mysql.createConnection(process.env.DATABASE_URL);

db.connect(err => {
    if (err) {
        console.error("Error conectando a MySQL:", err);
        return;
    }
    console.log("Conectado a MySQL 🚀");
});

app.get("/", (req, res) => {
    res.send("¡El servidor está funcionando correctamente!");
});

// Backend (Node.js)
app.get("/api/config", (req, res) => {
    res.json({ apiUrl: process.env.API_URL });
});

app.post('/api/import', authenticateToken, validateApiKey, upload.single('file'), async (req, res) => {
    if (!req.file) {
      return res.status(400).send('No file uploaded.');
    }
  
    const results = [];
  
    // Leer el CSV en una promesa para esperar que termine
    const parseCSV = () => new Promise((resolve, reject) => {
      fs.createReadStream(req.file.path)
        .pipe(csv({ separator: ';' }))
        .on('data', (data) => {
          // Detectar y limpiar BOM de las claves (solo afecta a la primera línea)
          const cleanedData = {};
          for (let key in data) {
            const cleanKey = key.replace(/^\uFEFF/, ''); // Eliminar BOM si existe al inicio
            let value = data[key];
            if (!value || ['nan', 'none'].includes(value.toLowerCase()) || value.toLowerCase().startsWith('sin ')) {
              value = '';
            } else {
              value = value.trim();
            }
            cleanedData[cleanKey] = value;
          }
  
          results.push({
            licencia: cleanedData['LICENCIA'] ? String(cleanedData['LICENCIA']).padStart(5, '0') : '',
            nombre_apellidos: cleanedData['CONDUCTOR'] || '',
            dni: cleanedData['DNI'] || '',
            email: cleanedData['CORREO ELECTRÉNICO'] || '',
            direccion: cleanedData['DIRECCION'] || '',
            codigo_postal: cleanedData['CODIGO POSTAL'] || '',
            numero_seguridad_social: cleanedData['NUMERO SEGURIDAD SOCIAL'] || ''
          });
        })
        .on('end', resolve)
        .on('error', reject);
    });
  
    // Función para hacer query que devuelve promesa
    const query = (sql, params) => new Promise((resolve, reject) => {
      db.query(sql, params, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  
    try {
      await parseCSV();
      await query('SET SQL_SAFE_UPDATES = 0');
      await query('DELETE FROM conductores');
      await query('ALTER TABLE conductores AUTO_INCREMENT = 1');
      for (const row of results) {
        const { licencia, nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social } = row;

         // Saltar si no hay licencia
        if (!licencia) {
          console.log('⚠️ Fila sin licencia, omitida:', row);
          continue;
        }

        
         // Comprobar si la licencia existe en la tabla licencias
         const licenciaExiste = await query('SELECT 1 FROM licencias WHERE LICENCIA = ?', [licencia]);
         if (licenciaExiste.length === 0) {
          console.log(`⚠️ Licencia no encontrada en la tabla licencias: ${licencia}. Fila omitida.`);
          continue; // saltamos esta fila
        }

        await query(
          `INSERT INTO conductores (nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia]
        );
      }
      await query('SET SQL_SAFE_UPDATES = 1');
      fs.unlinkSync(req.file.path);
      res.send('🚀 Importación completada correctamente');
    } catch (err) {
      console.error('Error en import:', err);
      try { fs.unlinkSync(req.file.path); } catch {}
      res.status(500).send('Error al procesar importación');
    }
  });
  //Registrar eventos
  async function registrarEvento(conductor, accion, fecha_str, enviarCorreo = true) {
    try {
      const sql = `
        INSERT INTO eventos
        (nombre_conductor, dni, licencia, vehiculo_modelo, matricula, email,
         num_seguridad_social, empresa, evento, fecha_hora)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const params = [
        conductor.nombre_conductor,
        conductor.dni,
        conductor.licencia,
        conductor.vehiculo_modelo,
        conductor.matricula,
        conductor.email,
        conductor.num_seguridad_social,
        conductor.empresa,
        accion,
        fecha_str
      ];
      
      await new Promise((resolve, reject) => {
        db.query(sql, params, (err, result) => {
          if (err) return reject(err);
          resolve(result);
        });
      });
  
      if (enviarCorreo) {
        const mailOptions = {
          from: 'controldeconductores@wetaximadrid.com',
          to: conductor.email,
          subject: `📋 Evento registrado: ${accion.replace(/_/g, ' ').toUpperCase()}`,
          text: `Hola ${conductor.nombre_conductor},
  
  Te informamos que se ha registrado el siguiente evento en tu control horario:

📌 Tipo de acción: ${accion.toUpperCase()}
🕒 Fecha y hora: ${fecha_str}
🆔 Licencia: ${licencia}
🚗 Vehículo: ${conductor.vehiculo_modelo} - ${conductor.matricula}
🏢 Empresa: ${conductor.empresa}

Este registro quedará guardado como parte de tu jornada laboral.
Si detectas algún error o consideras que debe realizarse alguna modificación, por favor contacta con el administrador de la aplicación escribiendo a: controldeconductores@wetaximadrid.com con tu Nombre y tu número de licencia.
En caso de no recibir ninguna notificación por tu parte, se entenderá que el registro es válido y real.

Saludos cordiales,
Control de Conductores
www.controldeconductores.com`
        };
  
        await transporter.sendMail(mailOptions);
      }
    } catch (err) {
      console.error('❌ Error al registrar evento:', err);
    }
  }
// Obtener todos los titulares (licencias)
app.get("/api/licencias", authenticateToken, validateApiKey, (req, res) => {
    db.query("SELECT * FROM licencias", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});
// Utilidad para normalizar campos "Sin algo"
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
    db.query("SELECT * FROM conductores ORDER BY estado = 'activo' DESC", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// Add this new endpoint after your other licencias endpoints
app.get("/api/licencias/empresa/:licencia", authenticateToken, validateApiKey, (req, res) => {
    const licencia = req.params.licencia;
    db.query("SELECT * FROM licencias WHERE licencia = ?", [licencia], (err, result) => {
        if (err) {
            console.error("Error fetching empresa data:", err);
            return res.status(500).json({ error: "Error en el servidor" });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Empresa no encontrada" });
        }
        res.json(result[0]);
    });
});

// Add this new endpoint for getting all conductors (protected with authentication)
app.get('/api/conductores/all', authenticateToken, validateApiKey, async (req, res) => {
    try {
        const query = `
            SELECT c.*, l.licencia 
            FROM conductores c 
            LEFT JOIN licencias l ON c.licencia = l.licencia
            ORDER BY c.nombre_apellidos`;
            
        const [conductores] = await db.promise().query(query);
        res.json(conductores);
    } catch (error) {
        console.error('Error fetching all conductores:', error);
        res.status(500).json({ message: 'Error fetching conductores data' });
    }
});

// Add this new endpoint for getting conductor by DNI (place it before the /api/conductores/:id endpoint)
app.get("/api/conductores/dni/:dni", authenticateToken, async (req, res) => {
    try {
        const dni = req.params.dni;
        
        const query = `
            SELECT 
                nombre_apellidos,
                dni,
                email,
                direccion,
                codigo_postal,
                numero_seguridad_social,
                licencia
            FROM conductores 
            WHERE dni = ?`;

        db.query(query, [dni], (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: "Error interno del servidor" });
            }
            if (results.length === 0) {
                return res.status(404).json({ message: "Conductor no encontrado" });
            }
            res.json(results[0]);
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});
// Keep existing /api/conductores/:id endpoint as is
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

// Actualizar un conductor por ID, para editar conductor
app.put("/api/conductores/:id", (req, res) => {
    const id = req.params.id;
    const { nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia, estado } = req.body;
    const query = "UPDATE conductores SET nombre_apellidos = ?, dni = ?, direccion = ?, codigo_postal = ?, email = ?, numero_seguridad_social = ?, licencia = ?, estado = ? WHERE id = ?";
    db.query(query, [nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social, licencia, estado, id], (err, result) => {
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
        licencia LIKE ? OR
        estado LIKE ? `;
    const searchTerm = `%${termino}%`;
    db.query(query, Array(9).fill(searchTerm), (err, result) => {
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
// Update the eventos endpoint
app.get('/api/eventos/:licencia?', authenticateToken, async (req, res) => {
    try {
        const licencia = req.params.licencia;
        const conductorNombre = req.query.conductor; // Add this line

        if (!licencia) {
            return res.status(400).json({ error: 'No se encontró la licencia asociada' });
        }

        const query = `
            SELECT e.evento, e.fecha_hora, e.nombre_conductor, e.dni
            FROM eventos e
            WHERE e.licencia = ?
            ${conductorNombre ? 'AND e.nombre_conductor = ?' : ''}
            ORDER BY e.fecha_hora ASC`;
        
        const queryParams = conductorNombre ? [licencia, conductorNombre] : [licencia];
        
        db.query(query, queryParams, (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Error en la base de datos' });
            }
            res.json(result || []);
        });
    } catch (error) {
        console.error('Unexpected error:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint para obtener los eventos por licencia
app.get('/api/eventos/detalles/:licencia', async (req, res) => {
    const { licencia } = req.params;
    
    try {
      db.query(`
        SELECT nombre_conductor, dni, licencia, vehiculo_modelo, matricula, email, 
               num_seguridad_social, empresa, evento, fecha_hora
        FROM eventos
        WHERE licencia = ?
        ORDER BY fecha_hora DESC
        LIMIT 50
      `, [licencia], (err, eventos) => {
        if (err) {
          console.error('❌ Error al obtener eventos por licencia:', err);
          return res.status(500).json({ message: 'Error al obtener eventos' });
        }
        res.json(eventos);
      });
    } catch (e) {
      console.error('❌ Error al obtener eventos por licencia:', e);
      res.status(500).json({ message: 'Error al obtener eventos' });
    }
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
                        isEmpresa: true
                    }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '24h' }
                );

                return res.json({
                    exists: true,
                    token,
                    licencias: result.map(lic => ({
                        licencia: lic.LICENCIA,
                        nombre: lic.NOMBRE_APELLIDOS,
                        matricula: lic.MATRICULA,
                        marca_modelo: lic.MARCA_MODELO,
                        dni: lic.DNI,
                        email: lic.EMAIL
                    }))
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

app.post('/api/login-conductor', (req, res) => {
  const { email, dni } = req.body;
  if (!email || !dni) return res.status(400).json({ message: 'Faltan datos' });

  db.query(`SELECT * FROM conductores WHERE email = ? AND dni = ?`, [email, dni], (err, results) => {
      if (err) {
          console.error('❌ Error en /login-conductor (verificación de existencia):', err);
          return res.status(500).json({ message: 'Error interno del servidor' });
      }

      if (results.length === 0) {
          return res.status(401).json({ message: '❌ Usuario no encontrado' });
      }

      const conductor = results[0];

      if (conductor.estado !== 'activo') {
          return res.status(403).json({ message: '❌ Usuario dado de baja, no puedes iniciar sesión' });
      }

      // Consulta completa con JOIN para obtener datos extendidos
      db.query(`
          SELECT c.nombre_apellidos AS nombre, c.licencia, c.email, c.dni, c.numero_seguridad_social,
                 l.marca_modelo AS vehiculo_modelo,
                 l.nombre_apellidos AS empresa, l.matricula
          FROM conductores c
          JOIN licencias l ON c.licencia = l.licencia
          WHERE c.email = ? AND c.dni = ?
      `, [email, dni], (err, rows) => {
          if (err) {
              console.error('❌ Error en /login-conductor (datos completos):', err);
              return res.status(500).json({ message: 'Error interno del servidor' });
          }

          if (rows.length === 0) {
              return res.status(401).json({ message: '❌ Usuario no encontrado' });
          }

          const usuario = rows[0];

          // Generar tokens UUID para session y csrf (no JWT para session id aquí)
          const sessionToken = uuidv4();
          const csrfToken = uuidv4();

          // Guardar en caché info relevante para eventos futuros
          conductorCache[usuario.licencia] = {
              nombre_conductor: usuario.nombre,
              dni: usuario.dni,
              licencia: usuario.licencia,
              vehiculo_modelo: usuario.vehiculo_modelo,
              matricula: usuario.matricula,
              email: usuario.email,
              num_seguridad_social: usuario.numero_seguridad_social,
              empresa: usuario.empresa
          };

          // Construir usuario sanitizado para respuesta
          const usuarioSanitizado = {
              nombre: usuario.nombre,
              licencia: usuario.licencia,
              email: usuario.email,
              vehiculo_modelo: usuario.vehiculo_modelo,
              empresa: usuario.empresa,
              matricula: usuario.matricula,
              token: sessionToken // este token es tipo UUID como en Python, no JWT aquí
          };

          // Configurar cookies como en Python
          const secureFlag = process.env.NODE_ENV === 'production';

          res.cookie('session_id', sessionToken, {
              httpOnly: true,
              secure: secureFlag,
              sameSite: 'Lax'
          });
          res.cookie('csrf_token', csrfToken, {
              secure: secureFlag,
              sameSite: 'Strict'
          });
          res.cookie('cookie_consent', 'true', {
              maxAge: 31536000 * 1000, // 1 año en ms
              httpOnly: false,
              secure: secureFlag,
              sameSite: 'Strict'
          });

          return res.status(200).json(usuarioSanitizado);
      });
  });
});
// Registrar evento
app.post('/api/registrar-fecha', async (req, res) => {
  const data = req.body;
  console.log('📥 Datos recibidos:', data);

  const accion = data.accion;
  const licencia = data.licencia;

  if (!licencia || !accion) {
    return res.status(400).json({ message: 'Faltan datos (licencia o acción)' });
  }

  let fecha_utc;
  try {
    fecha_utc = DateTime.fromISO(data.fecha_hora, { zone: 'utc' });
    if (!fecha_utc.isValid) throw new Error('Fecha inválida');
  } catch {
    return res.status(400).json({ message: 'Formato de fecha inválido' });
  }

  // Convertir a zona Madrid
  const zonaMadrid = 'Europe/Madrid';
  const fecha_local = fecha_utc.setZone(zonaMadrid);
  const fecha_str = fecha_local.toFormat('yyyy-MM-dd HH:mm:ss');

  let conductor = conductorCache.get(licencia);

  if (!conductor) {
    // Si la acción es inicio_jornada, lo cargamos de la base de datos
    if (accion === 'inicio_jornada') {
      const resultado = await queryAsync(`
        SELECT 
          c.nombre_apellidos AS nombre_conductor,
          c.dni,
          c.licencia,
          l.marca_modelo AS vehiculo_modelo,
          l.matricula,
          c.email,
          c.numero_seguridad_social AS num_seguridad_social,
          l.nombre_apellidos AS empresa
        FROM conductores c
        JOIN licencias l ON c.licencia = l.licencia
        WHERE c.licencia = ?
      `, [licencia]);
  
      if (resultado.length === 0) {
        return res.status(404).json({ message: 'Conductor no encontrado en la base de datos' });
      }
  
      conductor = resultado[0];
      conductorCache.set(licencia, conductor); // Ahora sí, lo guardamos en caché
    } else {
      return res.status(404).json({ message: 'Conductor no encontrado en caché. Debes iniciar jornada primero.' });
    }
  }
  // Consultas a base de datos: convertimos consultas sincronas a async con Promises
  function queryAsync(sql, params) {
    return new Promise((resolve, reject) => {
      db.query(sql, params, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  }

  try {
    if (accion === 'inicio_jornada') {
      const ultimoFin = await queryAsync(`
        SELECT fecha_hora FROM eventos
        WHERE licencia = ? AND evento = 'fin_jornada'
        ORDER BY fecha_hora DESC
        LIMIT 1
      `, [licencia]);

      if (ultimoFin.length > 0) {
        const ultimaFecha = DateTime.fromJSDate(ultimoFin[0].fecha_hora, { zone: 'utc' });
        const diff = fecha_utc.diff(ultimaFecha, 'minutes').minutes;
        if (diff < 2) {
          return res.status(429).json({ message: 'Debes esperar al menos 2 minutos después de finalizar la jornada para iniciar una nueva.' });
        }
      }
    }

    if (accion === 'inicio_descanso' || accion === 'fin_descanso') {
      const ultimoEvento = await queryAsync(`
        SELECT evento FROM eventos
        WHERE licencia = ?
        ORDER BY fecha_hora DESC
        LIMIT 1
      `, [licencia]);

      if (accion === 'inicio_descanso') {
        if (ultimoEvento.length > 0 && ultimoEvento[0].evento === 'inicio_descanso') {
          return res.status(400).json({ message: 'No se puede registrar un nuevo inicio de descanso sin finalizar el anterior.' });
        }
      }

      if (accion === 'fin_descanso') {
        if (ultimoEvento.length === 0 || ultimoEvento[0].evento !== 'inicio_descanso') {
          return res.status(400).json({ message: 'No se puede finalizar el descanso sin haberlo iniciado.' });
        }
      }
    }

    // Registrar evento en base de datos y enviar correo
    await registrarEvento(conductor, accion, fecha_str);

    // Si es inicio_jornada, programar eventos futuros
    if (accion === 'inicio_jornada') {
      const datosConductor = { ...conductor };

      const tiempos = [
        ["inicio_descanso", 120],
        ["fin_descanso", 240],
        ["inicio_descanso", 360],
        ["fin_descanso", 480],
        ["inicio_descanso", 600],
        ["fin_descanso", 720],
        ["fin_jornada", 840]
      ];

      // Fecha base en UTC
      const fechaBase = fecha_utc;

      tiempos.forEach(([nombreEvento, minutos]) => {
        // Sumar minutos y convertir a zona Madrid
        const fechaEvento = fechaBase.plus({ minutes: minutos }).setZone(zonaMadrid);
        const fechaEventoStr = fechaEvento.toFormat('yyyy-MM-dd HH:mm:ss');

        // Programar tarea con node-schedule para que se ejecute a la fecha exacta
        schedule.scheduleJob(fechaEvento.toJSDate(), async () => {
          console.log(`⏱ Ejecutando evento automático: ${nombreEvento} con fecha registrada: ${fechaEventoStr}`);
          await registrarEvento(datosConductor, nombreEvento, fechaEventoStr, true);
        });

        console.log(`📅 Evento automático '${nombreEvento}' agendado para: ${fechaEvento.toISO()}`);
      });
    }

    return res.json({ message: `✅ Evento "${accion}" registrado a las ${fecha_str}` });

  } catch (e) {
    console.error('❌ Error en /api/registrar-fecha:', e);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});
 // Enviar correo
app.post('/api/send-email', async (req, res) => {
    const { email, evento } = req.body;
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'tucorreo@gmail.com',
        pass: 'tu_contraseña_o_app_password'
      }
    });
  
    try {
      await transporter.sendMail({
        from: '"Notificación" <tucorreo@gmail.com>',
        to: email,
        subject: "Notificación de evento",
        text: `Hola, se ha registrado un nuevo evento: ${evento}`
      });
      res.json({ status: 'Correo enviado' });
    } catch (e) {
      console.error('❌ Error al enviar correo:', e);
      res.status(500).json({ message: 'Error al enviar correo' });
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
app.post('/api/recuperar-correo', (req, res) => {
  const { dni, licencia } = req.body;
  console.log('Petición /api/recuperar-correo recibida con:', { dni, licencia });

  if (!dni || !licencia) {
    console.warn('Faltan dni o licencia');
    return res.status(400).json({ error: 'DNI y Licencia son requeridos.' });
  }

  const sql = 'SELECT email FROM conductores WHERE dni = ? AND licencia = ?';
  db.query(sql, [dni.toUpperCase(), licencia.toUpperCase()], (err, results) => {
    if (err) {
      console.error('Error en consulta SQL:', err);
      return res.status(500).json({ error: 'Error en el servidor.' });
    }

    console.log('Resultados de la consulta:', results);

    if (results.length === 0) {
      return res.status(404).json({ error: 'No se encontró ningún correo para esos datos.' });
    }

    const email = results[0].email;
    console.log('Email encontrado:', email);
    res.json({ email });  // respuesta con la propiedad 'email'
  });
});

// Obtener info del conductor por licencia
app.get('/api/conductor/:licencia', (req, res) => {
    const { licencia } = req.params;
  
    if (!licencia) return res.status(400).json({ message: 'Falta la licencia' });
  
    db.query(
      `SELECT c.nombre_apellidos AS nombre, c.dni, c.licencia FROM conductores c WHERE licencia = ?`,
      [licencia],
      (err, results) => {
        if (err) {
          console.error('❌ Error en /api/conductor/:licencia:', err);
          return res.status(500).json({ message: 'Error al obtener el conductor' });
        }
  
        if (results.length === 0) {
          return res.status(404).json({ message: 'Conductor no encontrado' });
        }
  
        res.json(results[0]);
      }
    );
  });
  
  
// Update the conductores by licencia endpoint
app.get("/api/conductores/licencia/:licencia", authenticateToken, async (req, res) => {
    try {
        const licencia = req.params.licencia;
        
        // Updated query to match the expected structure
        const query = `
            SELECT DISTINCT
                c.dni,
                c.nombre_apellidos,
                c.email,
                c.licencia,
                c.estado
            FROM conductores c
            WHERE c.licencia = ?
            ORDER BY c.nombre_apellidos`;

        db.query(query, [licencia], (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: "Error interno del servidor" });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Add this new endpoint to get a single conductor by DNI
app.get("/api/conductores/:dni", authenticateToken, async (req, res) => {
    try {
        const dni = req.params.dni;
        
        const query = `
            SELECT 
                nombre_apellidos,
                dni,
                email,
                direccion,
                codigo_postal,
                numero_seguridad_social,
                licencia
            FROM conductores 
            WHERE dni = ?`;

        db.query(query, [dni], (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: "Error interno del servidor" });
            }
            if (results.length === 0) {
                return res.status(404).json({ message: "Conductor no encontrado" });
            }
            res.json(results[0]);
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});