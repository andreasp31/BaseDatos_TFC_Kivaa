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
    clave: { type: String, required: true }
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
    tipo: { type:String, required: true},
    ubicacion: { type:String, required: true},
    cualificacion: { type:Number, required: true},
    horario:{},
    enlace:{},
    foto:{}
})

const Usuario = mongoose.model("Usuario", usuarioEsquema);
const Locales = mongoose.model("Actividades",localesEsquema);

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
//Inscribirse a una de las actividades seleccionado la hora que nos interese
app.post("/api/actividades/inscribir", async(req,res)=>{
    const { actividadId, email, fechaHora } = req.body;
    try{
        //Buscar actividad y ver si hay plazas
        const actividad = await Actividades.findById(actividadId);
        let personaApuntada = false;

        for (let i = 0; i < actividad.personasApuntadas.length; i++) {
            if (actividad.personasApuntadas[i].usuarioEmail === email) {
                yaEstaApuntado = true;
                break;
            }
        }
        if (personaApuntada) {
            return res.status(400).json({ message: "Ya estás inscrito en esta actividad" });
        }
        if(actividad.plazas <= 0){
            return res.status(400).json({messahe:"No quedan plazas para esta actividad"});
        }
        await Actividades.findByIdAndUpdate(actividadId,
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
            res.json({message:"Te has inscrito correctamente"});
    }
    catch(error){
        res.status(500).json({ message: "Error al inscribirse" });
    }
})

//Cancelar la activadad que nos interese
app.delete("/api/actividades/cancelar",async(req,res)=>{
    const {actividadId, email} = req.body;
    try{
        const actividad = await Actividades.findById(actividadId);
        const hoy = new Date();
        const limite = new Date(actividad.fechaHora);
        limite.setHours(0, 0, 0, 0);

        if (hoy < limite) {
            // Antes de las 12 se borra usuario y se suma plaza
            await Actividades.findByIdAndUpdate(actividadId, {
                $pull: { personasApuntadas: { usuarioEmail: email } },
                $inc: { plazas: 1 } 
            });
        } else {
            // Después de las 12 se cambia a cancelado y no se recupera plaza
            await Actividades.findOneAndUpdate(
                { _id: actividadId, "personasApuntadas.usuarioEmail": email },
                { $set: { "personasApuntadas.$.estado": "cancelado_tarde" } });
            res.json({ message: "Cancelado tarde. La plaza no se libera." });
        }
    }
    catch(error){
        res.status(500).json({ message: "Error al cancelar la reserva" });
    }
})

//Cambiarle la hora a una de las reservas inscritas
app.put("/api/actividades/actualizarHora",async(req,res)=>{
    const {actividadId, email, nuevaHora} = req.body;
    try{
        const resultado = await Actividades.findOneAndUpdate(
            {
                _id: actividadId, 
                "personasApuntadas.usuarioEmail": email
            },
            {
                $set: { "personasApuntadas.$.hora": nuevaHora }
            },
            {new:true}
        );
        res.json({ message: "Hora actualizada con éxito", actividad: resultado });
    }
    catch(error){
        res.status(500).json({ message: "Error al actualizar la hora" });
    }
})

//Como crear una nueva actividad
app.post("/api/actividades/crear", async (req, res) => {
    const { nombre, descripcion, plazas, fechaHora, fecha } = req.body;
    try {
        const nuevaActividad = new Actividades({
            nombre,
            descripcion,
            plazas,
            fechaHora: fecha || fechaHora,
            personasApuntadas: []
        });
        await nuevaActividad.save();
        res.status(201).json({ message: "Actividad creada", actividad: nuevaActividad });
    } catch (error) {
        res.status(500).json({ message: "Error al crear actividad" });
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
//Permite al administrador eliminar los datos de las actividades
app.delete("/api/actividades/eliminar/:id", async (req, res) => {
    try {
        await Actividades.findByIdAndDelete(req.params.id);
        res.json({ message: "Actividad borrada" });
    } catch (error) {
        res.status(500).json({ message: "Error al borrar" });
    }
});

//Consultar la lista de todas las actividades
app.get("/api/actividades", async (req, res) => {
    try {
        const lista = await Actividades.find();
        res.json(lista);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener actividades" });
    }
});

//Concultar las actividades al que se está inscritas
app.get("/api/mis-actividades/:email", async (req, res) => {
    try {
        const misActividades = await Actividades.find({
            "personasApuntadas.usuarioEmail": req.params.email
        });
        res.json(misActividades);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener mis actividades" });
    }
});

// Iniciamos todo
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    connectarBd(); // Conectamos a la BD después de levantar el servidor
});