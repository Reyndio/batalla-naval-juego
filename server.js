const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = Number(process.env.PORT) || 3000;

const db = new sqlite3.Database('./batalla_naval.db', (err) => {
    if (err) {
        console.error('Error abriendo la base de datos: ' + err.message);
    } else {
        console.log('Conectado a la base de datos SQLite.');
        db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)', (createErr) => {
            if (createErr) console.error('Error creando la tabla: ' + createErr.message);
        });
    }
});

app.use(express.json());
app.use(express.static('.'));

// Development-pilot convenience routes. The legacy index/login flow remains untouched.
app.get('/pilot', (_req, res) => {
    res.sendFile(path.join(__dirname, 'pilot-2v2.html'));
});

app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', pilot: 'historical-2v2' });
});

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.run(sql, [username, hashedPassword], function(err) {
        if (err) {
            if (err.errno === 19) return res.status(409).json({ message: 'El nombre de usuario ya existe.' });
            return res.status(500).json({ message: 'Error al registrar el usuario.', error: err.message });
        }
        res.status(201).json({ message: 'Usuario registrado con éxito.', userId: this.lastID });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });

    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor.', error: err.message });
        if (!user) return res.status(404).json({ message: 'Usuario no encontrado.' });

        const isPasswordCorrect = bcrypt.compareSync(password, user.password);
        if (isPasswordCorrect) res.status(200).json({ message: 'Inicio de sesión exitoso.' });
        else res.status(401).json({ message: 'Contraseña incorrecta.' });
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Servidor corriendo en puerto ${port}`);
    console.log(`Piloto histórico 2v2 disponible en /pilot`);
});
