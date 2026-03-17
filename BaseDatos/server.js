const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const app = express();
app.use(express.json());
app.use(cors());

//nivel de seguridad
const SALT_ROUNDS = 10

const JWT_SECRET = process.env.JWT_SECRET;

const PORT = process.env.PORT || 3000;

// Definimos el Esquema
const usuarioEsquema = new mongoose.Schema({
    nombre: { type: String, required: true },
    apellidos: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    clave: { type: String, required: true },
    //añadir lista para los locales favoritos
    favoritos: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Locales"
    }]
});

//Esquemas de validacion
const RegistroSchema = z.object({
    nombre: z.string().min(2,"Nombre demasiado corto"),
    apellidos: z.string().min(2,"Apellidos obligatorios"),
    email: z.string().email("Email inválido"),
    clave: z.string().min(6, "La clave debe tener al menos 6 caracteres"),
    clave2: z.string()
}).refine((data) => data.clave === data.clave2, {
    message: "Las contraseñas no coinciden",
    path: ["clave2"],
});

const LoginSchema = z.object({
    email: z.string().email(),
    clave: z.string()
});

const localesEsquema = new mongoose.Schema({
    nombre: { type:String, required: true},
    tipo: { type:String, enum: ["Restaurante","Cafetería","Panadería","Supermercado"]},
    //como tiene que ser el campo ubicación para Google maps
    ubicacion: { 
        direccion: String,
        posicion:{
            //Siempre tiene que ser Point
            type:{type: String, default:"Point"},
            coordinates: {type:[Number], required:true}
        }
    },
    cualificacion: { type:Number, default: 0},
    horario: [String],
    enlace: String,
    foto: String
});

localesEsquema.index({"ubicacion.posicion":"2dsphere"});

const Usuario = mongoose.model("Usuario", usuarioEsquema);
const Locales = mongoose.model("Actividades",localesEsquema);

const localesCercanos = await localesEsquema.find({
    "ubicacion.posicion":{
        $near: {
            $geometry:{type: "Point", coordinates: [longitudUsuario, latidudUsuario]},
            $maxDistancia: 2000
        }
    }
})

// Función de conexión mejorada
async function connectarBd() {
    try {
        console.log("Iniciando conexión a MongoDB...");
        
        // Usamos la URI directamente o desde el env
        const uri = process.env.MONGODB_URI;

        await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 8000,
            family: 4,
        });

        console.log("¡Conectado a MongoDB con éxito!");

    } catch(error) {
        console.error("Error en conexión a MongoDB: ", error.message);
    }
}

// Ruta de Login confirmando si el correo están en los usuarios
app.post("/api/login", async (req, res) => {
    try {
        // Validar con zod
        const validacion = LoginSchema.safeParse(req.body);
        if (!validacion.success) return res.status(400).json({ message: "Datos inválidos" });

        const { email, clave } = validacion.data;

        const usuario = await Usuario.findOne({ email });
        if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });

        // BCRYPT,comparar contraseña enviada con el hash de la BD
        const esValida = await bcrypt.compare(clave, usuario.clave);
        if (!esValida) return res.status(401).json({ message: "Contraseña incorrecta" });

        // JWT,generar Token
        const token = jwt.sign(
            { id: usuario._id,nombre: usuario.nombre, role: usuario.role },
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({
            token,
            usuario: {
                id: usuario._id,
                nombre: usuario.nombre,
                email: usuario.email,
                role: usuario.role
            }
        });
    } catch(error) {
        res.status(500).json({ message: "Error del servidor" });
    }
});
//Registrarse con los datos y validando que los datos estén correctos
app.post("/api/registro", async (req, res) => {
    try {
        // Validar con zod
        const validacion = RegistroSchema.safeParse(req.body);
        if (!validacion.success) {
            const erroresFormateados = validacion.error.format();
            return res.status(400).json({ 
                message: "Error de validación",
                detalles: erroresFormateados 
            });
        }

        const { nombre, apellidos, email, clave } = validacion.data;

        const existeUsuario = await Usuario.findOne({ email });
        if (existeUsuario) {
            return res.status(400).json({ message: "El correo ya está registrado" });
        }

        //Hashear la contraseña
        const passwordHash = await bcrypt.hash(clave, SALT_ROUNDS);

        const nuevoUsuario = new Usuario({
            nombre,
            apellidos,
            email,
            clave: passwordHash // se guarda el hash
        });

        await nuevoUsuario.save();
        res.status(201).json({ message: "Usuario creado con éxito" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno" });
    }
});

//Como crear una nueva locales
app.post("/api/locales/crear", async (req, res) => {
    const { nombre, tipo, ubicacion, cualificacion, horario, enlace, foto } = req.body;
    try {
        const nuevolocal = new Locales({
            nombre,
            tipo,
            ubicacion,
            cualificacion,
            horario,
            enlace,
            foto
        });
        await nuevaActividad.save();
        res.status(201).json({ message: "Establecimiento añadido", local: nuevolocal });
    } catch (error) {
        res.status(500).json({ message: "Error al crear el establecimiento" });
    }
});

//Permite al administrador cambiar los datos de las locales
app.put("/api/locales/actualizar/:id", async (req, res) => {
    const { nombre, tipo, ubicacion, cualificacion, horario, enlace, foto } = req.body;
    try {
        const actualizado = await Locales.findByIdAndUpdate(
            req.params.id,
            { 
                nombre, 
                tipo, 
                ubicacion, 
                cualificacion,
                horario,
                enlace,
                foto 
            },
            { new: true }
        );
        res.json(actualizado);
    } catch (error) {
        res.status(500).json({ message: "Error al actualizar el establecimiento" });
    }
});
//Permite al administrador eliminar los datos de las locales
app.delete("/api/locales/eliminar/:id", async (req, res) => {
    try {
        await Locales.findByIdAndDelete(req.params.id);
        res.json({ message: "Actividad borrada" });
    } catch (error) {
        res.status(500).json({ message: "Error al borrar el establecimiento" });
    }
});

//Consultar la lista de todas las locales
app.get("/api/locales", async (req, res) => {
    try {
        const lista = await Locales.find();
        res.json(lista);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener locales" });
    }
});

//Concultar las locales que están en los favoritos del usuario
app.get("/api/mis-locales/:email", async (req, res) => {
    try {
        const misLocales = await Usuario.find({
            //Cambiar
            "favoritos.idLocal": req.params.email
        });
        res.json(misLocales);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener mis locales" });
    }
});

// Iniciamos todo
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    connectarBd(); // Conectamos a la BD después de levantar el servidor
});