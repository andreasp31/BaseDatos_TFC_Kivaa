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
    foto: { type:String}
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
    nombre: { type: String, required: true },
    tipo: { type: String, required: true, enum: ["Restaurante", "Cafetería", "Supermercado", "Panadería"] },
    direccion: { type: String, required: true }, // La dirección escrita
    // Cordenadas para el mapa
    latitud: { type: Number, required: true },
    longitud: { type: Number, required: true },
    cualificacion: { type: Number, default: 0 },
    horario: { type: String, required: true },
    enlace: { type: String },
    foto: { type: String },
    // Para favorito una lista de IDs de usuarios que dan like 
    favoritos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Usuario' }]
});

const reseñaEsquema = new mongoose.Schema({
    localId: { type: mongoose.Schema.Types.ObjectId, ref: 'Locales' },
    usuarioNombre: { type: String },
    comentario: { type: String },
    estrellas: { type: Number },
    fecha: { type: Date, default: Date.now }
});

const Usuario = mongoose.model("Usuario", usuarioEsquema);
const Locales = mongoose.model("Locales", localesEsquema);
const Reseña = mongoose.model("Reseña", reseñaEsquema);

// Función de conexión mejorada
async function connectarBd() {
    try {
        console.log("Iniciando conexión a MongoDB...");
        
        // Usamos la URI directamente o desde el env
        await mongoose.connect(process.env.MONGO_DB);
    insertarDatosPrueba();
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

//Inscribirse a una de las actividades seleccionado la hora que nos interese
app.post("/api/locales/comentario", async(req,res)=>{
    const { localId, email, fechaHora } = req.body;
    try{
        //Buscar locales
        const local = await Locales.findById(localId);

        await Locales.findByIdAndUpdate(actividadId,
            {
                $push: { 
                    personasApuntadas: { 
                        usuarioEmail: email,
                        hora: fechaHora } 
                },
                //Borrar una plaza 
                $inc: { plazas: -1 }
            },
            //Tener documento actualizado
            {new: true});
            res.json({message:"Has añadido un comentario correctamente"});
    }
    catch(error){
        res.status(500).json({ message: "Error al comentar" });
    }
})

//Crear una reseña
app.post("/api/locales/resena", async (req, res) => {
    try {
        const nuevaReseña = new Reseña(req.body);
        await nuevaReseña.save();
        res.status(201).json({ message: "Reseña añadida" });
    } catch (error) {
        res.status(500).json({ message: "Error al comentar" });
    }
});

//Como crear un nuevo local
app.post("/api/locales/crear", async (req, res) => {
    const { nombre, descripcion, plazas, fechaHora, fecha } = req.body;
    try {
        const actualizado = await Locales.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        res.json(actualizado);
    } catch (error) {
        res.status(500).json({ message: "Error al actualizar" });
    }
});

//Permite al administrador cambiar los datos de las actividades
app.put("/api/actividades/actualizar/:id", async (req, res) => {
    const { nombre, descripcion, plazas, fecha } = req.body;
    try {
        const actualizado = await Actividades.findByIdAndUpdate(
            req.params.id,
            { 
                nombre, 
                descripcion, 
                plazas, 
                fechaHora: fecha 
            },
            { new: true }
        );
        res.json(actualizado);
    } catch (error) {
        res.status(500).json({ message: "Error al actualizar" });
    }
});

//Permite al administrador eliminar los datos de los locales
app.delete("/api/locales/eliminar/:id", async (req, res) => {
    try {
        await Locales.findByIdAndDelete(req.params.id);
        res.json({ message: "Local borrado" });
    } catch (error) {
        res.status(500).json({ message: "Error al borrar" });
    }
});

// Obtener todos los locales
app.get("/api/locales", async (req, res) => {
    try {
        const lista = await Locales.find();
        res.json(lista);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener locales" });
    }
});

//Consultar la lista de busqueda de los locales
app.get("/api/locales/buscar", async (req, res) => {
    const { nombre } = req.query;
    try {
        const resultados = await Locales.find({
            // Busca sin importar mayúsculas
            nombre: { $regex: nombre, $options: "i" } 
        });
        res.json(resultados);
    } catch (error) {
        res.status(500).json({ message: "Error en la búsqueda" });
    }
});

//Concultar las actividades al que en favoritos
app.get("/api/mis-locales/:usuarioId", async (req, res) => {
    try {
        // Buscamos locales donde el ID del usuario esté en el array de favoritos
        const misFavoritos = await Locales.find({ favoritos: req.params.usuarioId });
        res.json(misFavoritos);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener favoritos" });
    }
});

// Dar o quitar Like como Favoritos
app.post("/api/locales/favorito", async (req, res) => {
    const { localId, usuarioId } = req.body;
    try {
        const local = await Locales.findById(localId);
        const yaEsFavorito = local.favoritos.includes(usuarioId);

        if (yaEsFavorito) {
            // Si ya está se quita
            await Locales.findByIdAndUpdate(localId, { $pull: { favoritos: usuarioId } });
            res.json({ message: "Quitado de favoritos" });
        } else {
            // Si no está se le añade
            await Locales.findByIdAndUpdate(localId, { $push: { favoritos: usuarioId } });
            res.json({ message: "Añadido a favoritos" });
        }
    } catch (error) {
        res.status(500).json({ message: "Error al gestionar favorito" });
    }
});

// Iniciamos todo
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    connectarBd(); // Conectamos a la BD después de levantar el servidor
});

//Datos de prueba
const insertarDatosPrueba = async () => {
    const localesPrueba = [
        {
            nombre: "Celicioso Ourense",
            tipo: "Cafetería",
            direccion: "Rúa do Paseo, Ourense",
            latitud: 42.3414,
            longitud: -7.8638,
            horario: "09:00 - 21:00",
            enlace: "https://kivaa.app",
            foto: "https://images.unsplash.com/photo-1509042239860-f550ce710b93"
        },
        {
            nombre: "O Fogón de Vigo",
            tipo: "Restaurante",
            direccion: "Rúa de Rosalía de Castro, Vigo",
            latitud: 42.2365,
            longitud: -8.7145,
            horario: "13:00 - 23:00",
            enlace: "https://kivaa.app",
            foto: "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4"
        },
        {
            nombre: "Panadería Sano y Salvo",
            tipo: "Panadería",
            direccion: "Praza de España, Pontevedra",
            latitud: 42.4310,
            longitud: -8.6444,
            horario: "08:00 - 15:00",
            enlace: "https://kivaa.app",
            foto: "https://images.unsplash.com/photo-1555507036-ab1f4038808a"
        },
        {
            nombre: "Vigo BioMarket",
            tipo: "Supermercado",
            direccion: "Rúa do Príncipe, Vigo",
            latitud: 42.2380,
            longitud: -8.7210,
            horario: "09:00 - 21:30",
            enlace: "https://kivaa.app",
            foto: "https://images.unsplash.com/photo-1542838132-92c53300491e"
        }
    ];

    try {
        // Borramos lo que haya antes para no duplicar cada vez que reinicies
        await Locales.deleteMany({}); 
        // Insertamos los nuevos
        await Locales.insertMany(localesPrueba);
        console.log("Locales insertados correctamente");
    } catch (error) {
        console.error("Error insertando datos:", error);
    }
};