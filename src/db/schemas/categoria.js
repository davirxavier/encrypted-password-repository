const mongoose = require("mongoose")

// Todo separar coleções
const categoriaSchema = mongoose.Schema
({
    nome:{
        type: String,
        required: true
    },
    emailDono : {
        type: String,
        required: true
    }
})

const categoriaModel = mongoose.model("categoria", categoriaSchema)
module.exports = categoriaModel
module.exports.categoriaSchema = categoriaSchema
