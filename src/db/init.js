const mongoose = require('mongoose')
const uri = process.env.DB_URI || "mongodb://localhost/eprdb"

mongoose.connect(uri, {useNewUrlParser: true, useUnifiedTopology: true}).then(r => {
    console.log("Connected to db successfully");
}).catch(e => {
    console.log("Error connecting to db: " + e);
})

module.exports = { url: uri }
