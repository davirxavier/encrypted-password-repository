const mongoose = require('mongoose')

const userSchema = mongoose.Schema
({
    email: {
        type: String,
        unique: true,
        require: true
    },
    senha: {
        type: String,
        require: true
    }
})

const usuarioModel = mongoose.model('usuario', userSchema)
module.exports = usuarioModel