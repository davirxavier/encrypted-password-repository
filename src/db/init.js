const mongoose = require('mongoose')
const uri = process.env.DB_URI || "mongodb://localhost/eprdb"
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })

module.exports = { url: uri }
