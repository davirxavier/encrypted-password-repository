const CryptoJs = require("crypto-js")

function encrypt(data, secret)
{
    return CryptoJs.AES.encrypt(data, secret).toString();
}

function decrypt(encrypted, secret)
{
    return CryptoJs.AES.decrypt(encrypted, secret).toString(CryptoJs.enc.Utf8);
}

module.exports.encrypt = encrypt
module.exports.decrypt = decrypt