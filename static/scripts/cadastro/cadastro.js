import {validateEmail} from "../validators.js";
import {validatePassword} from "../validators.js";

const buttonCadastrar = document.getElementById("buttonCadastrar")

const inputSenha = document.getElementById("inputpassword")
const inputSenhaCon = document.getElementById("inputpasswordcon")

const inputEmail = document.getElementById("inputemail")
const inputEmailCon = document.getElementById("inputemailcon")

const checkboxTerms = document.getElementById("checkboxTerms")
const checkboxTermsDiv = document.getElementById("checkboxTermsDiv")

buttonCadastrar.onclick = function (e)
{
    let email = inputEmail.value
    let emailcon = inputEmailCon.value
    let senha = inputSenha.value
    let senhacon = inputSenhaCon.value

    if (email !== undefined && email.length > 0 && emailcon !== undefined && emailcon.length > 0
        && email === emailcon && senha === senhacon
        && senha !== undefined && senha.length > 0 && senhacon !== undefined && senhacon.length > 0
        && validatePassword(senha) && validateEmail(email))
    {
        if (!checkboxTerms.checked)
        {
            checkboxTermsDiv.style = "border-style: solid; border-width: 2px; border-color: red;"
            return
        }
        else
        {
            checkboxTermsDiv.style = ""
        }

        if (buttonCadastrar.classList.contains("red-outline"))
        {
            buttonCadastrar.classList.remove("red-outline")
        }

        $.ajax("/cadastro",
            {
                type: "POST",
                data: JSON.stringify({
                    email: email,
                    emailcon: emailcon,
                    senha: senha,
                    senhacon: senhacon
                }),
                contentType: "application/json; charset=utf-8",
                statusCode: {
                    200: function (response)
                    {
                        new duDialog("Sucesso", "Cadastro realizado com sucesso! Realize seu login.", {
                            callbacks:{
                                cancelClick: function ()
                                {
                                    window.location.href = "/login"
                                }
                            }
                        })
                    },
                    500: function (response)
                    {
                        new duDialog("Erro", "Erro desconhecido, tente novamente.")
                    },
                    400: function (response)
                    {
                        new duDialog("Erro", "Entradas inválidas, tente novamente.")
                    },
                    409: function (response)
                    {
                        new duDialog("Erro", "Esse e-mail já existe, escolha outro.")
                    }
                }
            })
    }
    else
    {
        buttonCadastrar.classList.add("red-outline")
    }
}

$(document).on('input', '#inputemail', function ()
{
    if (validateEmail(inputEmail.value))
    {
        if (inputEmail.classList.contains("red-outline"))
        {
            inputEmail.classList.remove("red-outline")
        }
        inputEmail.classList.add("green-outline")
    }
    else
    {
        if (inputEmail.classList.contains("green-outline"))
        {
            inputEmail.classList.remove("green-outline")
        }
        inputEmail.classList.add("red-outline")
    }
})

$(document).on('input', '#inputpassword', function ()
{
    if (validatePassword(inputSenha.value))
    {
        if (inputSenha.classList.contains("red-outline"))
        {
            inputSenha.classList.remove("red-outline")
        }
        inputSenha.classList.add("green-outline")
    }
    else
    {
        if (inputSenha.classList.contains("green-outline"))
        {
            inputSenha.classList.remove("green-outline")
        }
        inputSenha.classList.add("red-outline")
    }
})

$(document).on('input','#inputpasswordcon',function ()
{
    if (inputSenha.value === inputSenhaCon.value)
    {
        if (inputSenhaCon.classList.contains("red-outline"))
        {
            inputSenhaCon.classList.remove("red-outline")
        }
        inputSenhaCon.classList.add("green-outline")
    }
    else
    {
        if (inputSenhaCon.classList.contains("green-outline"))
        {
            inputSenhaCon.classList.remove("green-outline")
        }
        inputSenhaCon.classList.add("red-outline")
    }
})

$(document).on('input','#inputemailcon',function ()
{
    if (inputEmail.value === inputEmailCon.value)
    {
        if (inputEmailCon.classList.contains("red-outline"))
        {
            inputEmailCon.classList.remove("red-outline")
        }
        inputEmailCon.classList.add("green-outline")
    }
    else
    {
        if (inputEmailCon.classList.contains("green-outline"))
        {
            inputEmailCon.classList.remove("green-outline")
        }
        inputEmailCon.classList.add("red-outline")
    }
})
