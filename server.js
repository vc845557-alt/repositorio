// ===============================
// Importar dependencias
// ===============================
const express = require("express");
const bcrypt = require("bcryptjs");

// Crear la aplicación
const app = express();

// Puerto del servidor
const PORT = 3000;

// Permitir recibir datos en formato JSON
app.use(express.json());

// ===============================
// Base de datos simulada
// ===============================
const usuariosDB = [];

// ===============================
// REGISTRO DE USUARIOS
// POST /api/register
// ===============================
app.post("/api/register", async (req, res) => {

    try {

        // Obtener los datos enviados desde Postman
        const { username, password } = req.body;

        // Validar que lleguen los datos
        if (!username || !password) {
            return res.status(400).json({
                error: "El usuario y la contraseña son obligatorios."
            });
        }

        // Verificar si el usuario ya existe
        const usuarioExiste = usuariosDB.find(
            user => user.username === username
        );

        if (usuarioExiste) {
            return res.status(400).json({
                error: "El usuario ya existe."
            });
        }

        // Encriptar la contraseña
        const salt = await bcrypt.genSalt(10);
        const passwordEncriptada = await bcrypt.hash(password, salt);

        // Guardar usuario
        usuariosDB.push({
            username: username,
            password: passwordEncriptada
        });

        // Respuesta exitosa
        res.status(201).json({
            mensaje: "Usuario registrado correctamente."
        });

    } catch (error) {

        // Mostrar el error en la terminal
        console.error(error);

        res.status(500).json({
            error: "Error interno del servidor al registrar."
        });

    }

});

// ===============================
// LOGIN
// POST /api/login
// ===============================
app.post("/api/login", async (req, res) => {

    try {

        const { username, password } = req.body;

        // Validar datos
        if (!username || !password) {

            return res.status(400).json({
                error: "Debe ingresar usuario y contraseña."
            });

        }

        // Buscar usuario
        const usuario = usuariosDB.find(
            user => user.username === username
        );

        // Validar existencia
        if (!usuario) {

            return res.status(401).json({
                error: "Error en la autenticación."
            });

        }

        // Comparar contraseña
        const passwordCorrecta = await bcrypt.compare(
            password,
            usuario.password
        );

        if (passwordCorrecta) {

            return res.status(200).json({
                mensaje: "Autenticación satisfactoria."
            });

        }

        return res.status(401).json({
            error: "Error en la autenticación."
        });

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            error: "Error interno del servidor al autenticar."
        });

    }

});

// ===============================
// Ruta principal (opcional)
// ===============================
app.get("/", (req, res) => {

    res.send("API funcionando correctamente");

});

// ===============================
// Iniciar servidor
// ===============================
app.listen(PORT, () => {

    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);

});