// 1. Importar las librerías que instalamos
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// 2. Inicializar la aplicación Express
const app = express();
const port = 3000; // El puerto donde se ejecutará nuestro servidor

// 3. Conectar a la base de datos (o crearla si no existe)
const db = new sqlite3.Database('./batalla_naval.db', (err) => {
    if (err) {
        console.error("Error abriendo la base de datos: " + err.message);
    } else {
        console.log("Conectado a la base de datos SQLite.");
        // Crear la tabla de usuarios si no existe
        db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)', (err) => {
            if (err) {
                console.error("Error creando la tabla: " + err.message);
            }
        });
    }
});

// 4. Middlewares: funciones que se ejecutan en cada petición
app.use(express.json()); // Para poder entender los datos JSON que envía el frontend
app.use(express.static('.')); // Para servir archivos estáticos como index.html, css, etc. desde la carpeta actual

// 5. Definir las "rutas" o "endpoints" de nuestra API

// --- Ruta para Registrar un nuevo usuario ---
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Usuario y contraseña son requeridos." });
    }

    // Hashear (encriptar) la contraseña antes de guardarla
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.run(sql, [username, hashedPassword], function(err) {
        if (err) {
            // El código 19 significa que el usuario ya existe (violación de la restricción UNIQUE)
            if (err.errno === 19) {
                return res.status(409).json({ message: "El nombre de usuario ya existe." });
            }
            return res.status(500).json({ message: "Error al registrar el usuario.", error: err.message });
        }
        res.status(201).json({ message: "Usuario registrado con éxito.", userId: this.lastID });
    });
});

// --- Ruta para Iniciar Sesión ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Usuario y contraseña son requeridos." });
    }

    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) {
            return res.status(500).json({ message: "Error en el servidor.", error: err.message });
        }
        if (!user) {
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        // Comparar la contraseña enviada con la hasheada en la BD
        const isPasswordCorrect = bcrypt.compareSync(password, user.password);

        if (isPasswordCorrect) {
            res.status(200).json({ message: "Inicio de sesión exitoso." });
        } else {
            res.status(401).json({ message: "Contraseña incorrecta." });
        }
    });
});


// 6. Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});