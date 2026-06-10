const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { dir } = require('console');

const app = express();
app.use(express.json());
app.use(cors());

//Para el guardado de imágenes
const dirUploads = path.join(__dirname, 'uploads');

// Comprobamos si existe si no la creamos a la fuerza
if (!fs.existsSync(dirUploads)) {
    fs.mkdirSync(dirUploads, { recursive: true });
    console.log("Carpeta 'uploads' creada correctamente en:", dirUploads);
}


// Configuración de almacenamiento para Multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, dirUploads);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });
app.use('/uploads', express.static('uploads'));

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
    fotoPerfil: { type: String, default: null }
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
    direccion: { type: String, required: true },
    // coordenadas mapa
    latitud: { type: Number, required: true },
    longitud: { type: Number, required: true },
    calificacion: { type: Number, default: 0 },
    horario: { type: String, required: true },
    enlace: { type: String },
    foto: { type: String },
    // una lista de ids de usuarios que le dieron "like"
    favoritos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Usuario' }]
});

const reseñaEsquema = new mongoose.Schema({
    localId: { type: mongoose.Schema.Types.ObjectId, ref: 'Locales', required: true },
    usuarioId: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
    usuarioNombre: {type: String , required: true},
    comentario: {type: String , required: true},
    estrellas: {type: Number , required: true, min: 1, max: 5},
    fecha: { type: Date, default: Date.now }
});

const Usuario = mongoose.model("Usuario", usuarioEsquema);
const Locales = mongoose.model("Locales",localesEsquema);
const Comentarios = mongoose.model("Comentarios", reseñaEsquema);

//Middleware para proteger rutas con jwt
const verificarToken = (req, res, next) =>{
    const authCabecera = req.headers["authorization"];
    //Formato 
    const token = authCabecera && authCabecera.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: "Acceso denegado. No se proporcionó un token." });
    }
    try{
        const verificado = jwt.verify(token, JWT_SECRET);
        req.usuario = verificado;
        next();
    }
    catch(error){
        console.error("ERROR EN EL MIDDLEWARE DE TOKEN:", error.message);
        return res.status(403).json({ message: "Token inválido o caducado." });
        
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
            { id: usuario._id,nombre: usuario.nombre, role: usuario.role, apellidos: usuario.apellidos, clave: usuario.clave},
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({
            token,
            usuario: {
                id: usuario._id,
                nombre: usuario.nombre,
                apellidos: usuario.apellidos,
                email: usuario.email,
                role: usuario.role,
                clave: usuario.clave,
                fotoPerfil: usuario.fotoPerfil
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

//ruta para actualizar los datos del usuario
app.put('/api/usuarios/actualizar',verificarToken, upload.single('fotoPerfil'), async (req, res) => {
  try {
    const usuarioId = req.usuario.id;
    const { nombre, apellidos } = req.body;

    let datosActualizar = {
      nombre: nombre,
      apellidos: apellidos
    };

    if (req.file) {
      const urlFotoPublica = `http://10.0.2.2:3000/uploads/${req.file.filename}`;
      datosActualizar.fotoPerfil = urlFotoPublica;
    }
    const usuarioActualizado = await Usuario.findByIdAndUpdate(
      usuarioId,
      datosActualizar,
      { returnDocument: "after" }
    );

    if (!usuarioActualizado) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    res.status(200).json(usuarioActualizado);

  } catch (error) {
    console.error("Error al actualizar usuario en el backend:", error);
    res.status(500).json({ mensaje: "Error interno del servidor", error: error.message });
  }
});

//Ruta para eliminar la cuenta de un usuario por el ID
app.delete("/api/usuarios/eliminar/:id",verificarToken, async(req,res)=>{
    try{
        const usuarioId = req.params.id;
        if (!usuarioId) {
            return res.status(400).json({ message: "El ID de usuario es requerido." });
        }
        const usuarioEliminado = await Usuario.findByIdAndDelete(usuarioId);
        if (!usuarioEliminado) {
            return res.status(404).json({ message: "El usuario no existe o ya ha sido eliminado." });
        }
        return res.status(200).json({ 
            success: true,
            message: "Usuario eliminado correctamente" 
        });
    }
    catch(error){
        console.error("Error en el servidor al eliminar usuario:", error);
        return res.status(500).json({ 
            message: "Error interno del servidor al procesar la solicitud." 
        });
    }
})

//Consultar la lista de todas los locales
app.get("/api/locales", async (req, res) => {
    try {
        const lista = await Locales.find().sort({ calificacion: -1 });
        res.json(lista);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener locales" });
    }
});

app.get("/api/locales/buscar", async (req, res) => {
    const { nombre } = req.query;
    try {
        const resultados = await Locales.find({
            nombre: { $regex: nombre, $options: "i" } 
        });
        res.json(resultados);
    } catch (error) {
        res.status(500).json({ message: "Error en la búsqueda" });
    }
});

//Ruta para obtener locales recomendados
app.get("/api/locales/sugeridos", async (req, res) => {
    try{
        const localesSugeridos = await Locales.find().sort({ calificacion: -1 }).limit(4);
        res.status(200).json(localesSugeridos || []);
    }
    catch(error){
        console.error("Error al obtener locales sugeridos:" ,error);
        res.status(500).json({message: "Error al obtener las sugerencias"});
    }
});

//Ruta para coger todos los favoritos del usuario que está iniciado
app.get("/api/locales/favoritos",verificarToken, async(req, res)=>{
    try{
        console.log("Usuario decodificado del token:", req.usuario);
        const usuarioId = req.usuario.id; 
        if (!usuarioId) {
            return res.status(400).json({ message: "No se encontró el ID de usuario en el token" });
        }
        console.log("Buscando favoritos para el usuario ID:", usuarioId);
        const listaFavoritos = await Locales.find({favoritos: usuarioId});
        return res.json(listaFavoritos);
    }
    catch(error){
        console.error("Error:", error);
        res.status(500).json({message:"Error al obtener la lista de favoritos"})
    }
});

//Como crear un nuevo local
app.post("/api/locales/crear", upload.single('foto'), async (req, res) => {
    try {
        const { nombre, tipo, direccion, web, enlace, latitud, longitud, horarios, horario, calificacion } = req.body;
        if (!nombre || !tipo || !direccion || !latitud || !longitud) {
            return res.status(400).json({ message: "Faltan campos obligatorios" });
        }
        const datosLocal = {
            nombre: nombre.trim(),
            tipo,
            direccion: direccion.trim(),
            latitud: parseFloat(latitud),
            longitud: parseFloat(longitud),
            enlace: web ? web.trim() : (enlace ? enlace.trim() : ""),
            horario: horarios ? horarios : (horario ? horario : ""),
            calificacion: calificacion ? parseInt(calificacion) : 0
        };
        if (req.file) {
            datosLocal.foto = `http://10.0.2.2:3000/uploads/${req.file.filename}`;
        } else if (req.body.foto) {
            // Si pasan directamente una URL 
            datosLocal.foto = req.body.foto;
        }
        const nuevoLocal = new Locales(datosLocal);
        await nuevoLocal.save();
        res.status(201).json({ message: "Local creado con éxito", local: nuevoLocal });
    } catch (error) {
        res.status(500).json({ message: "Error al crear el local", detalles: error.message });
    }
});

//Ruta para añadir local favoritos
app.post("/api/locales/favorito",verificarToken, async(req, res)=>{
    try{
        const {localId} = req.body;
        const usuarioId = req.usuario.id || req.usuario._id;
        if (!usuarioId) {
            return res.status(400).json({ message: "El ID de usuario no es válido o llegó vacío" });
        }
        const local = await Locales.findById(localId);
        if(!local){
            return res.status(404).json({ message: "Local no encontrado"});
        }
        const estaFavorito = local.favoritos.includes(usuarioId);
        //si ya está en favoritos se quita al dar al icono
        if(estaFavorito){
            await Locales.findByIdAndUpdate(localId, {$pull: { favoritos: usuarioId}});
            res.json({favorito: false, message: "Quitando local de mis favoritos"});
        }
        else{
            //addToSet para evitar duplicados y añadirlo a favoritos
            await Locales.findByIdAndUpdate(localId, {$addToSet: { favoritos: usuarioId}});
            res.json({favorito: true, message: "Añadiendo local a mis favoritos"});
        }
    }
    catch(error){
        console.error("Error en favoritos: ", error);
        res.status(500).json({message: "Error al procesar el favorito"});
    }
});

//Permite al administrador cambiar los datos de las locales
app.put("/api/locales/actualizar/:id", async (req, res) => {
    const { nombre, tipo, ubicacion, calificacion, horario, enlace, foto } = req.body;
    try {
        const actualizado = await Locales.findByIdAndUpdate(
            req.params.id,
            { 
                nombre, 
                tipo, 
                ubicacion, 
                calificacion,
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

//Para buscar un local según el id
app.get("/api/locales/:id", async (req, res) =>{
    try{
        const local = await Locales.findById(req.params.id);
        if(!local) {
            return res.status(404).json({mensaje: "Local no encontrado."})
        }
        res.json(local);
    }
    catch(error){
        res.status(500).json({ error: "Error al encontrar local" });
    }
});

//Obtener los comentarios de un usuario
app.get("/api/misResenas",verificarToken, async(req, res)=>{
    try{
        const usuarioId = req.usuario.id;
        const misComentarios = await Comentarios.find({ usuarioId }).populate('localId', 'nombre').sort({ fecha: -1 });
        res.json(misComentarios);
    }
    catch(error){
        res.status(500).json({message: "Error al obtener mis reseñas"});
    }
});

//Ruta para crear las reseñas
app.post("/api/locales/resena", verificarToken, async(req, res)=>{
    try{
        const { localId, usuarioNombre, comentario, estrellas} = req.body;
        const usuarioId = req.usuario.id;
        const nuevaResena = new Comentarios({
            localId,
            usuarioId,
            usuarioNombre,
            comentario,
            estrellas,
            fecha: new Date()
        });
        await nuevaResena.save();
        //recalcular la media de estrellas
        const todasResenas = await Comentarios.find({localId: localId});
        let sumarEstrellas = 0;
        for (let i=0; i<todasResenas.length; i++){
            sumarEstrellas = sumarEstrellas + todasResenas[i].estrellas;
        }
        const mediaNota = Number((sumarEstrellas/todasResenas.length).toFixed(1));
        await Locales.findByIdAndUpdate(localId, {calificacion: mediaNota})
        res.status(201).json(nuevaResena);
    }
    catch(error){
        res.status(500).json({message: "Error al comentar"})
    }
});

//Obtener todos los comentarios de un local
app.get("/api/locales/:id/resenas", async(req,res)=>{
    try{
        //Ordenados por fecha
        const comentarios = await Comentarios.find({
            localId: req.params.id
        }).sort({fecha: -1});
        res.json(comentarios);
    }
    catch(error){
        res.status(500).json({message: "Error al obtener las reseñas del local"});
    }
});

//Para editar las reseñas manualmente
app.put("/api/resenas/actualizar/:id", verificarToken, async(req, res)=>{
    try{
        const { id } = req.params;
        const { comentario, estrellas } = req.body;
        const resenaOriginal = await Comentarios.findById(id);
        if (!resenaOriginal) {
            return res.status(404).json({ message: "Reseña no encontrada" });
        }
        const localId = resenaOriginal.localId;
        const resenaActualizada = await Comentarios.findByIdAndUpdate(
            id,
            { 
                comentario, 
                estrellas, 
                fecha: new Date()
            },
            //devuelve la reseña ya modificada
            { new: true }
        );
        const todasResenas = await Comentarios.find({ localId: localId });
        
        let sumarEstrellas = 0;
        for (let i = 0; i < todasResenas.length; i++) {
            sumarEstrellas = sumarEstrellas + todasResenas[i].estrellas;
        }
        const mediaNota = Number((sumarEstrellas / todasResenas.length).toFixed(1));
        await Locales.findByIdAndUpdate(localId, { calificacion: mediaNota });
        res.status(200).json(resenaActualizada);
    }
    catch(error){
        console.error("Error al editar la reseña:", error);
        res.status(500).json({message: "Error al obtener mis reseñas"});
    }
});

app.delete("/api/resenas/eliminar/:id", async(req, res) =>{
    try{
        const resenaEliminada = await Comentarios.findByIdAndDelete(req.params.id);
        if(!resenaEliminada){
            return res.status(404).json({ message: "La reseña no existe" });
        }
        res.json({message: "Reseña eliminada correctamente"});
    }
    catch(error){
        console.error("Error al eliminar la reseña:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
})

//Ruta para estádisticas
app.get('/api/admin/estadisticas', async(req, res)=>{
    try{
        const totalLocales = await Locales.countDocuments();
        const totalUsuarios = await Usuario.countDocuments({ role: 'user' });
        res.json({
            locales: totalLocales,
            usuarios: totalUsuarios
        })
    }
    catch(Error){
        res.status(500).json({message: "Error al obtener las estadísticas"});
    }
});

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
            calificacion: 7,
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
            calificacion: 8,
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
            calificacion: 5,
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
            calificacion: 4,
            horario: "09:00 - 21:30",
            enlace: "https://kivaa.app",
            foto: "https://images.unsplash.com/photo-1542838132-92c53300491e"
        }
    ];

    try {
        // Borramos lo que haya antes para no duplicar cada vez que reinicies
        await Locales.deleteMany({}); 
        // Insertamos los nuevos
        const localesAnadidos = await Locales.insertMany(localesPrueba);
        console.log("Locales insertados correctamente");
        await Comentarios.deleteMany({});
        const ejemploUsuario = await Usuario.findOne({ email: "andrea@gmail.com"});
        if(ejemploUsuario){
            const localComentar = localesAnadidos[0];
            const comentarioPrueba = new Comentarios({
                localId: localComentar._id,
                usuarioId: ejemploUsuario._id,
                usuarioNombre: ejemploUsuario.nombre,
                comentario: "Las mejores tartas sin gluten, el trato es espectacular!",
                estrellas: 5,
                fecha: new Date("2026-02-14")
            });
            const comentarioPrueba2 = new Comentarios({
                localId: localComentar._id,
                usuarioId: new mongoose.Types.ObjectId(),
                usuarioNombre: "Claudia",
                comentario: "Todo muy rico y el personal muy amable",
                estrellas: 4,
                fecha: new Date("2026-04-29")
            });
            await comentarioPrueba.save();
            await comentarioPrueba2.save();
            const mediaInicial = Number(((5 + 4) / 2).toFixed(1));
            await Locales.findByIdAndUpdate(localComentar._id, { calificacion: mediaInicial });
        }
    } catch (error) {
        console.error("Error insertando datos:", error);
    }
};