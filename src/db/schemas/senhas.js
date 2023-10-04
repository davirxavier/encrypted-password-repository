const mongoose = require("mongoose")

const senhaSchema = mongoose.Schema
({
    descricao:{
        type: String,
        required: true
    },

    username:{
        type: String,
        required: true
    },

    senha_cript:{
        type: String,
        required: true
    },

    categoria:{
        type: mongoose.ObjectId,
        required: true
    }
})

const senhaModel = mongoose.model("senha", senhaSchema)
module.exports = senhaModel