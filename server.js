// Importación de las dependencias necesarias
const express = require('express');
const bcrypt = require('bcryptjs');

// Inicialización de la aplicación Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para permitir que el servidor interprete JSON en el cuerpo de las peticiones
app.use(express.json());

// "Base de datos" simulada en memoria para almacenar los usuarios registrados
const usuariosDB = [];

/**
 * SERVICIO DE REGISTRO
 * Endpoint: POST /api/register
 * Descripción: Recibe un usuario y contraseña, cifra la contraseña y lo guarda.
 */
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validación: Verificar que los campos no estén vacíos
        if (!username || !password) {
            return res.status(400).json({ error: "El usuario y la contraseña son obligatorios." });
        }

        // Validación: Verificar si el usuario ya se encuentra registrado
        const usuarioExiste = usuariosDB.find(user => user.username === username);
        if (usuarioExiste) {
            return res.status(400).json({ error: "El nombre de usuario ya está en uso." });
        }

        // Seguridad: Cifrar la contraseña antes de guardarla (Genera un salt y aplica el hash)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Guardar el nuevo usuario en nuestra base de datos simulada
        usuariosDB.push({
            username: username,
            password: hashedPassword
        });

        // Respuesta exitosa de creación
        return res.status(201).json({ mensaje: "Usuario registrado con éxito de forma segura." });

    } catch (error) {
        // Manejo de errores internos del servidor
        return res.status(500).json({ error: "Error interno del servidor al registrar." });
    }
});

/**
 * SERVICIO DE INICIO DE SESIÓN (AUTENTICACIÓN)
 * Endpoint: POST /api/login
 * Descripción: Recibe usuario y contraseña, y valida si las credenciales son correctas.
 */
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validación: Verificar que se envíen ambos campos
        if (!username || !password) {
            return res.status(400).json({ error: "Por favor, ingrese usuario y contraseña." });
        }

        // Buscar el usuario en la base de datos simulada
        const usuario = usuariosDB.find(user => user.username === username);

        // Si el usuario no existe, devuelve error de autenticación de inmediato
        if (!usuario) {
            return res.status(401).json({ error: "Error en la autenticación. Usuario o contraseña incorrectos." });
        }

        // Comparar la contraseña ingresada con la contraseña cifrada guardada
        const contraseñaValida = await bcrypt.compare(password, usuario.password);

        // Si la contraseña coincide, la autenticación es exitosa
        if (contraseñaValida) {
            return res.status(200).json({ mensaje: "Autenticación satisfactoria" });
        } else {
            // Si la contraseña no coincide, devuelve error de autenticación
            return res.status(401).json({ error: "Error en la autenticación. Usuario o contraseña incorrectos." });
        }

    } catch (error) {
        // Manejo de errores internos del servidor
        return res.status(500).json({ error: "Error interno del servidor al autenticar." });
    }
});

// Inicialización del servidor para que escuche en el puerto configurado
app.listen(PORT, () => {
    console.log(`Servidor web corriendo correctamente en http://localhost:${PORT}`);
});