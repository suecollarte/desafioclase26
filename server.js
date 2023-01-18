/*============================[Modulos]============================*/
import express from "express";
import session from "express-session";
import exphbs from 'express-handlebars';
import path from 'path';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { userModel } from './models/usuarios.model.js';
import { config } from './utils/configMongo.js';
import { logger } from "./src/utils/logger.config.js";
import compression from 'compression';

import cluster from 'cluster'
import { cpus } from 'os'
dotenv.config();

import passport from "passport";
import { Strategy } from "passport-local";
const LocalStrategy = Strategy;




/* === cluster ===*/



/* =============minimast ====*/
import util from 'util';


/*========= */

import { fork } from 'child_process';

const forkedProcess = fork('./random.js');



/*======= minimist ====*/
import minimist from "minimist";

process.on('exit', (code)=>{
    let infoErr = {}
    console.log('exit code',code);

    switch (code) {
        case 5:
            infoErr = {
                descripcion: 'error de tipo',
                numeros: numeros,
                tipos: tipos
            }
            break;
        case -4:
            infoErr = {
                descripcion: 'Entrada vacia'
            }
            break;
        case 0:
            console.log('Ejecucion finalizada!');    
    }
    console.log(infoErr)
});

process.on('uncaughtException', (err)=>{
    console.log('Error', err);
    process.exit(2)
});

//const args = minimist(process.argv.slice(2));
//const numeros = args._;
const numeros=[1, 2, 3, 4];
/* Primera valdiacion: Los datos de entrada no deben estar vacios*/
if (numeros.length === 0) {
    console.log('args vacio')
    process.exit(-4);
}
console.log('Datos recibidos', numeros);

console.log('numeros: ', numeros);
const tipos = tipo(numeros);
console.log('Tipos de los datos: ', tipos);

/* Segunda valdiacion: Tipos de datos deben ser numeros*/
validacionTipo(tipos);

const suma = numeros.reduce((a, b)=>{
    let acumulador = 0;
    acumulador = parseInt(a) + parseInt(b);
    return acumulador;
});

const info = {
    datos: {
        numeros: numeros,
        promedio: suma/numeros.length,
        max: Math.max.apply(null, numeros),
        min: Math.min.apply(null, numeros),
        ejecutable: process.title,
        pid: process.pid
    }
}
console.log(info);

/* =================== [ Utilitarios ] ===================*/
function tipo(array) {
    let arrayTipes = [];

    array.forEach(element => {
        arrayTipes.push(typeof(element));
    });

    return arrayTipes;
}

function validacionTipo(array) {
    console.log('Se dispara la validacion 2')
    array.forEach(element => {
        if (element != 'number') {
            console.log(element, 'number')
            process.exit(5)
        }
    });
}

/*============================[Middlewares]============================*/


/*----------- Passport -----------*/

/*
    SOLUCION: Passport LocalStrategy, utiliza dos valores esperados llamados username y password, por lo que
    dentro del formulario 'login' debe contener estos dos imputs con el su respectivo nombre.

    En clase no se reconocia el login porque teniamos nombre/password en lugar de username/password en el HTML.
*/

passport.use(new LocalStrategy(
    async function(username, password, done) {
        console.log(`${username} ${password}`)
        const strConn = `mongodb://${config.db.host}:${config.db.port}/${config.db.dbName}`
        const conn = await mongoose.connect(strConn, config.db.options);
        //Logica para validar si un usuario existe
        //const existeUsuario = await usuariosDB.find(usuario => usuario.username == username);
        const existeUsuario = await userModel.find(usuario => usuario.username == username);
        console.log(existeUsuario);

        if (!existeUsuario) {
            return done(null, false);
        } else {

            const match = await verifyPass(existeUsuario, password);
            if(!match){
                return done(null, false);
            }

            return done(null, existeUsuario);
        }
        await mongoose.disconnect();
        console.log('Base de datos desconectada!');
    }
));
//correlacionar con los datos
passport.serializeUser((username, done)=>{
    done(null, usuario.username);
});

passport.deserializeUser((username, done)=>{
    
 //  const existeUsuario = usuariosDB.find(usuario => usuario.username == username);
    const strConn = `mongodb://${config.db.host}:${config.db.port}/${config.db.dbName}`
    const conn =  mongoose.connect(strConn, config.db.options);
    //Logica para validar si un usuario existe
    //const existeUsuario = await usuariosDB.find(usuario => usuario.username == username);
    const existeUsuario =  userModel.find(usuario => usuario.username == username);
    console.log(existeUsuario);
    done(null, existeUsuario);
    mongoose.disconnect();
});

/*----------- Session -----------*/

const app = express();
app.use(session({
    secret: "algo",
    resave: true,
    saveUninitialized: false,
    cookie: {
        maxAge: 864000 //20 seg
    }
}))

app.use(passport.initialize());
app.use(passport.session());

//Metodos de Auth
async function generateHashPassword(password){
    const hashPassword = await bcrypt.hash(password, 10);
    return hashPassword;
}

async function verifyPass(usuario, password) {
    const match = await bcrypt.compare(password, usuario.password);
    console.log(`pass login: ${password} || pass hash: ${ usuario.password}`)
    return match;
}

/*----------- Motor de plantillas -----------*/
app.set('views', 'src/views');
app.engine('.hbs', exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(app.get('views'), 'layouts'),
    extname: '.hbs'
}));
app.set('view engine', '.hbs');

app.use(express.urlencoded({extended: true}));
app.use(express.json());

function isAuth(req, res, next) {
    if(req.isAuthenticated()){
        next()
    } else {
        res.redirect('/login')
    }
}

/*============================[Base de Datos]============================*/
//const usuariosDB = [];

/*============================[Rutas]============================*/
const modoCluster = process.argv[2] == 'CLUSTER'

if (modoCluster && cluster.isPrimary) {
    const numCPUs = cpus().length

    console.log(`Número de procesadores: ${numCPUs}`)
    console.log(`PID MASTER ${process.pid}`)

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork()
    }

    cluster.on('exit', worker => {
        console.log('Worker', worker.process.pid, 'died', new Date().toLocaleString())
        cluster.fork()
    })
} else {


app.get('/', (req, res)=>{
    //res.redirect('/login')
    const primes = []
        const max = Number(req.query.max) || 1000
        for (let i = 1; i <= max; i++) {
            if (isPrime(i)) primes.push(i)
        }
        res.json(primes)
})

app.get('/login', (req, res)=>{
    res.render('login.hbs');
})

app.get('/register', (req, res)=>{
    res.render('registro.hbs');
})

app.post('/login', passport.authenticate('local',  {successRedirect: '/datos', failureRedirect: '/login-error'} ));

app.get('/datos', isAuth, (req, res)=>{
    if(!req.user.contador){
        req.user.contador = 1
    } else {
        req.user.contador++
    }
    const datosUsuario = {
        nombre: req.user.username,
        direccion: req.user.direccion
    }
    res.render('datos', {contador: req.user.contador, datos: datosUsuario});
})

app.get('/info', (req,res)=>{
    const ll= process.cwd() + '\nId del proceso:'+process.pid
    + '\nVersion de NodeJS:'+process.version
    + '\nNombre del proceso:'+process.title
    + '\nSistema Operativo:'+process.platform
    + '\n\nUso memoria:'+ util.inspect(process.memoryUsage(), {showHidden: false, depth: 12, colorize: true })  ;
    logger.info(`Parámetros ${util.inspect(process.memoryUsage(), {showHidden: false, depth: 12, colorize: true})} `);

    const infor ={
        directorio : ll
    }
    
    res.render('infor',{infor:infor});
})
/* compression */
app.get('/info-zip', compression(), (req,res)=>{
    const ll= process.cwd() + '\nId del proceso:'+process.pid
    + '\nVersion de NodeJS:'+process.version
    + '\nNombre del proceso:'+process.title
    + '\nSistema Operativo:'+process.platform
    + '\n\nUso memoria:'+ util.inspect(process.memoryUsage(), {showHidden: false, depth: 12, colorize: true})  ;
    logger.info(`Parámetros ${util.inspect(process.memoryUsage(), {showHidden: false, depth: 12, colorize: true})} `);

    const infor ={
        directorio : ll
    }
    
    res.render('infor',{infor:infor});
})





app.post('/register', async (req, res)=>{
    const {username, password, direccion } = req.body;
    const strConn = `mongodb://${config.db.host}:${config.db.port}/${config.db.dbName}`
    const conn =  mongoose.connect(strConn, config.db.options);
    //Logica para validar si un usuario existe
    //const existeUsuario = await usuariosDB.find(usuario => usuario.username == username);
    const newUsuario =  userModel.find(usuario => usuario.username == username);
    //const newUsuario = usuariosDB.find(usuario => usuario.username == username);
    if (newUsuario) {
        res.render('registro-error')
    } else {
        const newUser = {username, password: await generateHashPassword(password), direccion};
        console.log(newUser);
        //usuariosDB.push(newUser);
        await userModel.insertMany(newUser);
        res.redirect('/login')
    }
    await mongoose.disconnect();
})

app.get('/logout', (req, res)=> {
    req.logOut(err => {
        res.redirect('/');
    });
})

app.get('/login-error', (req, res)=>{
    res.render('login-error');
})

app.get('*', (req, res) => {
    const {url, method } = req;
    logger.warn(`Ruta ${method} ${url} no implementada`)
    res.send(`Ruta ${method} ${url} no está implementada`);
})
/*===== FORK ===*/

/*============================[Rutas]============================*/
let visitas = 0;
app.get('/', (req, res)=>{
   res.send(`Cantidad de visitas: ${++visitas}`);
});

app.get('/random/:cant', (req, res)=>{
    console.log(cant);
    let suma = 0;
    for (let i = 0; i < cant; i++) {
        suma += i;
    }
    res.send(`suma: ${suma}`);
})

app.get('/calculo-nobloq', (req, res)=>{
    forkedProcess.send('INICIA');
    forkedProcess.on('message', msg => {
        console.log('mensaje desde el procesos secundario:');
        console.log(msg);
    });
    res.send('Sometido en segundo plano');
})

app.get('*', (req, res) => {
    const {url, method } = req;
    logger.warn(`Ruta ${method} ${url} no implementada`)
    res.send(`Ruta ${method} ${url} no está implementada`);
})
/*============================[Servidor]============================*/
const PORT = process.env.PORT;
const server = app.listen(PORT, ()=>{
    console.log(`Servidor escuchando en puerto ${PORT}`);
    logger.info(`Servidor express escuchando en el puerto ${PORT}`);
})
server.on('error', error=>{
    console.error(`Error en el servidor ${error}`);
    logger.error(`Error en servidor: ${error}`);
});
server.on('request', (req,res)=>{
    let {url}= req
    if (url == '/random') {
    
    forkedProcess.send('Inicia');
    forkedProcess.on('message', msg => {
        logger.info('mensaje desde el procesos secundario random:');
        console.log(msg);
    });
    

    }
    if (url == '/info') {
    
        forkedProcess.send('Inicia');
        forkedProcess.on('message', msg => {
            logger.info('mensaje desde el procesos secundario info:');
            console.log(msg);
        });
        
    
        }
    
})
//termino cluster
}
function isPrime(num) {
    if ([2, 3].includes(num)) return true;
    else if ([2, 3].some(n => num % n == 0)) return false;
    else {
        let i = 5, w = 2;
        while ((i ** 2) <= num) {
            if (num % i == 0) return false
            i += w
            w = 6 - w
        }
    }
    return true
}