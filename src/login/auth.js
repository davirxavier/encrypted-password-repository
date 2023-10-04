const bcrypt = require('bcryptjs')
const LocalStrategy = require('passport-local').Strategy
const passport = require('passport')
const mongoose = require('mongoose')
const userModel = mongoose.model('usuario')
const ObjectId = mongoose.Types.ObjectId

function findUser(email, callback)
{
    userModel.findOne({ email: email }, (err, obj) =>
    {
        callback(err, obj)
    })
}

function findUserById(id, callback)
{
    userModel.findOne({ _id: ObjectId(id) }, (err, doc) =>
    {
        callback(err, doc);
    });
}

passport.serializeUser(function(user, done)
{
    done(null, user._id);
});

passport.deserializeUser(function(id, done)
{
    findUserById(id, function(err,user)
    {
        done(err, user);
    });
});

passport.use("local", new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'senha'
    },
    (username, password, done) =>
    {
        findUser(username, (err, user) =>
        {
            if (err) { return done(err) }

            // usuário inexistente
            if (!user) { return done(null, false) }

            // comparando as senhas
            bcrypt.compare(password, user.senha, (err, isValid) =>
            {
                if (err) { return done(err) }
                if (!isValid) { return done(null, false) }
                return done(null, user)
            })
        })
    }
));

module.exports = function(passport)
{
}
