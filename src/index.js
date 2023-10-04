// Inicialização do DOTENV
require('dotenv').config()

// Inicialização do Express e middlewares
const passport = require('passport')
const session = require('express-session')
const MongoStore = require('connect-mongo')(session)
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const handlebars = require('express-handlebars')
const bcrypt = require("bcryptjs")
const sslify = require("express-sslify")

const path = require("path")
const validators = require("./cadastro/validators")

// Inicialização do DB
const db = require('./db/init')
const mongoose = require("mongoose")
const usuarioModel = require('./db/schemas/usuario')
const categoriaModel = require('./db/schemas/categoria')
const senhaModel = require('./db/schemas/senhas')

// Crypt
const crypt = require("./crypt/crypt")
const router = express.Router();
const basePath = '/epr/';

//////////////////////////////////////////////////////////////////////////////////////////////////
// Sessão
require('./login/auth')(passport);
router.use(session({
    store: new MongoStore({
        url: db.url,
        ttl: 60 * 60
    }),
    secret: process.env.CRYPT_SECRET || 'secretteste',
    resave: false,
    saveUninitialized: false,
    secure: true
}))

//////////////////////////////////////////////////////////////////////////////////////////////////
// Middlewares
app.use(basePath, express.static(__dirname + '/../static'));
router.use(passport.initialize({userProperty: "email"}));
router.use(passport.session({}));
router.use(bodyParser.json())
router.use(bodyParser.urlencoded({extended: true}))

// Enforce HTTPS
if ((process.env.ENFORCE_HTTPS || "").toLocaleLowerCase() === "true")
{
    router.use(sslify.HTTPS({ trustProtoHeader: true }))
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//Handlebars
app.engine('handlebars', handlebars({defaultLayout: 'main'}))
app.set('view engine', 'handlebars')

//////////////////////////////////////////////////////////////////////////////////////////////////
// Middleware para checagem de autenticação
function authenticationMiddleware()
{
    return function (req, res, next)
    {
        if (req.isAuthenticated())
        {
            return next()
        }

        res.redirect('login?fail=notlogged')
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Login routes
router.get("/login", function (req, res)
{
    if (req.isAuthenticated())
    {
        res.redirect("index")
        return;
    }

    let errorvisible = "hidden"
    let errortext = ""
    if (req.query.fail)
    {
        errorvisible = "visible"
        if (req.query.fail === "incorrect")
        {
            errortext = "E-mail ou senha incorretos."
        } else if (req.query.fail === "notlogged")
        {
            errortext = "Faça login para acessar essa página."
        }
    }

    const stylesheets = "<link rel='stylesheet' href='css/login.css'>";
    res.render("login", {
        title: "Login | EPR",
        stylesheets: stylesheets,
        errorvisible: errorvisible,
        errortext: errortext
    })
})
router.post('/login', function (req, res, next)
{
    passport.authenticate("local", {
        successRedirect: "index",
        failureRedirect: "login?fail=incorrect"
    }, function (err, user, info)
    {
        if (err)
        {
            return next(err);
        }
        if (!user)
        {
            return res.redirect("login?fail=incorrect")
        }

        req.logIn(user, function (err)
        {
            if (err)
            {
                return next(err);
            }
            return res.redirect("index");
        });
    })(req, res, next)
})
router.get("/logout", authenticationMiddleware(), (req, res) =>
{
    req.logout(() => res.redirect("login"));
})

//////////////////////////////////////////////////////////////////////////////////////////////////
// FAQ
router.get("/faq", (req, res) => {
    const stylesheets = "<link rel='stylesheet' href='css/login.css'>";
    res.render("faq", {
        title: "Sobre | EPR",
        stylesheets: stylesheets,
        errorvisible: "hidden"
    });
})

//////////////////////////////////////////////////////////////////////////////////////////////////
// Cadastrar
router.get("/cadastro", (req, res) =>
{
    const stylesheets = "<link rel='stylesheet' href='css/cadastro.css'>";
    res.render("cadastro", {
        title: "Cadastro | EPR",
        stylesheets: stylesheets,
        errorvisible: "hidden"
    })
})
router.get("/termos", (req, res) =>
{
    res.status(200)
    res.render("termos", {
        title: "Termos de Uso | EPR"
    })
})
router.get("/privacidade", (req, res) =>
{
    res.status(200)
    res.render("privacidade", {
        title: "Política de Privacidade | EPR"
    })
})
router.post("/cadastro", (req, res) =>
{
    let email = req.body.email
    let emailcon = req.body.emailcon
    let senha = req.body.senha
    let senhacon = req.body.senhacon

    if (email !== undefined && email.length > 0 && emailcon !== undefined && emailcon.length > 0
        && email === emailcon && senha === senhacon
        && senha !== undefined && senha.length > 0 && senhacon !== undefined && senhacon.length > 0
        && validators.validatePassword(senha) && validators.validateEmail(email))
    {
        bcrypt.genSalt((err, salt) =>
        {
            bcrypt.hash(senha, salt, (err, hash) =>
            {
                if (!err)
                {
                    new usuarioModel({
                        email: email,
                        senha: hash
                    }).save().then(function ()
                    {
                        res.status(200)
                        res.redirect("login")
                        res.send("Ok")
                    }).catch(function (error)
                    {
                        if (error.code === 11000)
                        {
                            res.status(409)
                            res.send("Email já existe.")
                        }
                        else
                        {
                            sendError500(req, res, error)
                        }
                    })
                }
                else
                {
                    sendError500(req, res, err)
                }
            })
        })
    }
    else
    {
        res.status(400)
        res.send("Entrada(s) inválida(s).")
    }
})

//////////////////////////////////////////////////////////////////////////////////////////////////
// Index routes
router.get("/index", authenticationMiddleware(), function (req, res)
{
    const stylesheets = "<link rel='stylesheet' href='css/index.css'>";
    res.render("index", {
        title: "Index | EPR",
        stylesheets: stylesheets
    })
})
router.get("/", function (req, res)
{
    res.redirect("login")
})

//////////////////////////////////////////////////////////////////////////////////////////////////
// Categoria routes
router.get("/categorias", authenticationMiddleware(), (req, res) =>
{
    let search = req.query.search

    usuarioModel.findById(req.session.passport.user).lean().then(user =>
    {
        var busca = {emailDono: user.email}
        if (search)
        {
            busca.nome = { "$regex": search, "$options": "i" }
            console.log(busca)
        }

        categoriaModel.find(busca).then(categorias =>
        {
            res.status(200)
            res.json(categorias)
        }).catch(err => sendError500(req, res, err))
    })
})
router.delete("/categorias", authenticationMiddleware(), (req, res) =>
{
    let id = req.body.catID
    let senha = req.body.senha
    if (id === undefined || senha === undefined)
    {
        res.status(400)
        res.send("Categoria ou senha inválida.")
    } else
    {
        usuarioModel.findById(req.session.passport.user).lean().then(user =>
        {
            bcrypt.compare(senha, user.senha, (err, isValid) =>
            {
                if (isValid)
                {
                    categoriaModel.deleteOne({_id: new mongoose.Types.ObjectId(id), emailDono: user.email}).then(() =>
                    {
                        res.status(200)
                        res.send("Removida com sucesso.")
                    }).catch(err => sendError500(req, res, err))
                } else
                {
                    res.status(403)
                    res.send("Senha incorreta.")
                }
            })
        })
    }
})
router.post("/categorias", authenticationMiddleware(), function (req, res)
{
    let nome = req.body.nome
    let senha = req.body.senha

    let id = new mongoose.Types.ObjectId((req.session.passport.user))
    usuarioModel.findById(id).then((user) =>
    {
        bcrypt.compare(senha, user.senha, (err, isValid) =>
        {
            if (err)
            {
                sendError500(req, res, err)
                return
            }

            if (!isValid)
            {
                res.status(403)
                res.send("Senha incorreta.")
                return
            }

            if (nome !== undefined && nome.length > 0 && senha !== undefined && senha.length > 0)
            {
                let categoria = new categoriaModel({
                    nome: nome,
                    emailDono: user.email,
                    senhas: []
                })
                categoria.save()

                res.status(200)
                res.send("Ok")
            } else
            {
                res.status(400)
                res.send("Nome ou senha inválidos.")
            }
        })
    })
})
router.put("/categorias", authenticationMiddleware(), function (req, res)
{
    let nome = req.body.nome
    let senha = req.body.senha
    let idcat = req.body.id

    let id = new mongoose.Types.ObjectId((req.session.passport.user))
    usuarioModel.findById(id).then((user) =>
    {
        bcrypt.compare(senha, user.senha, (err, isValid) =>
        {
            if (err)
            {
                sendError500(req, res, err)
                return
            }

            if (!isValid)
            {
                res.status(403)
                res.send("Senha incorreta.")
                return
            }

            if (nome !== undefined && nome.length > 0 && senha !== undefined && senha.length > 0
                && id !== undefined && idcat.length > 0)
            {
                categoriaModel.findById(idcat).then((categoria) =>
                {
                    categoria.nome = nome
                    categoria.save().then(() =>
                    {
                        res.status(200)
                        res.send("Ok")
                    }).catch(err => sendError500(req, res, err))
                }).catch(err => sendError500(req, res, err))
            } else
            {
                res.status(400)
                res.send("Nome ou senha inválidos.")
            }
        })
    })
})

//////////////////////////////////////////////////////////////////////////////////////////////////
// Senhas routes
router.get("/senhas", authenticationMiddleware(), (req, res) =>
{
    usuarioModel.findById(req.session.passport.user).then(user =>
    {
        categoriaModel.find({emailDono: user.email}).then(categorias =>
        {
            const ids = []
            categorias.forEach(v =>
            {
                ids.push(v._id)
            })
            senhaModel.find({
                "categoria": {
                    $in: ids
                }
            }).then(passwords =>
            {
                res.status(200)
                res.json(passwords)
            }).catch(err => sendError500(req, res, err))
        }).catch(err => sendError500(req, res, err))
    })
})

router.post("/senhas", authenticationMiddleware(), (req, res) =>
{
    let descricao = req.body.descricao
    let usuario = req.body.username
    let novaSenha = req.body.senha_cript
    let senhaConta = req.body.senha
    let categoriaID = req.body.categoria

    if( descricao !== undefined && descricao.length > 0 && usuario !== undefined && usuario.length > 0
        && novaSenha !== undefined && novaSenha.length > 0 && senhaConta !== undefined && senhaConta.length > 0
        && categoriaID !== undefined && categoriaID.length > 0)
    {
        usuarioModel.findById(req.session.passport.user).then(user =>
        {
            bcrypt.compare(senhaConta, user.senha, (err, isValid) =>
            {
                if (err)
                {
                    sendError500(req, res, err)
                    return
                }

                if (!isValid)
                {
                    res.status(403)
                    res.send("Senha incorreta.")
                    return
                }

                new senhaModel({
                    descricao: descricao,
                    username: usuario,
                    senha_cript: crypt.encrypt(novaSenha, senhaConta),
                    categoria: categoriaID
                }).save().then(() =>
                {
                    res.status(200)
                    res.send("Ok")
                }).catch(err => sendError500(req, res, err))
            })
        }).catch(err =>
        {
            console.log(err)
            sendError500(req, res, err)
        })
    }
    else
    {
        res.status(400)
        res.send("Entrada(s) inválida(s).")
    }
})

router.put("/senhas", authenticationMiddleware(), (req, res)=>
{
    let descricao = req.body.descricao
    let usuario = req.body.username
    let novaSenha = req.body.senha_cript
    let senhaConta = req.body.senha
    let senhaID = req.body.senhaID

    if( descricao !== undefined && descricao.length > 0 && usuario !== undefined && usuario.length > 0
        && novaSenha !== undefined && novaSenha.length > 0 && senhaConta !== undefined && senhaConta.length > 0
        && senhaID !== undefined && senhaID.length > 0)
    {
        usuarioModel.findById(req.session.passport.user).then(user =>
        {
            bcrypt.compare(senhaConta, user.senha, (err, isValid) =>
            {
                if (err)
                {
                    sendError500(req, res, err)
                    return
                }

                if (!isValid)
                {
                    res.status(403)
                    res.send("Senha incorreta.")
                    return
                }

                senhaModel.findById(senhaID).then(senhaRes =>
                {
                    senhaRes.descricao = descricao
                    senhaRes.username = usuario
                    senhaRes.senha_cript = crypt.encrypt(novaSenha, senhaConta)

                    senhaRes.save().then(() =>
                    {
                        res.status(200)
                        res.send("Senha atualizada com sucesso.")
                    }).catch(err => sendError500(req, res, err))
                }).catch(err => sendError500(req, res, err))
            })
        }).catch(err => sendError500(req, res, err))
    }
    else
    {
        res.status(400)
        res.send("Entrada(s) inválida(s).")
    }
})

router.delete("/senhas", authenticationMiddleware(), (req, res)=>
{
    let senhaID = req.body.senhaID

    if(senhaID !== undefined && senhaID.length > 0)
    {
        usuarioModel.findById(req.session.passport.user).then(user =>
        {
            senhaModel.deleteOne({_id: senhaID}).then(() =>
            {
                res.status(200)
                res.send("Senha apagada com sucesso.")
            }).catch(err => sendError500(req, res, err))
        })
    }
    else
    {
        res.status(400)
        res.send("Entradas inválidas.")
    }
})

app.use(basePath, router);
//////////////////////////////////////////////////////////////////////////////////////////////////
// Listening
const port = parseInt(process.env.PORT) || 3000
const hostname = process.env.BIND_IP || "0.0.0.0"

app.listen(port, hostname, () =>
{
    console.log("Server listening at " + hostname + ":" + port)
})

function sendError500(req, res, err)
{
    return function (req, res, err)
    {
        res.status(500)
        res.send("Erro desconhecido.")
    }
}

/*bcrypt.genSalt((err, salt) =>
{
    bcrypt.hash("davi", salt, (err, hash) =>
    {
        console.log(hash)
        new usuarioModel({
            email: "davi@a.com",
            senha: hash
        }).save();
    })
})*/
