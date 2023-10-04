import {dialogoExcluir} from "./deleteCategory.js";
import {editarCategoriaDialog} from "./editCategory.js";
import {newPasswordDialog} from "./newPassword.js";
import {editarSenhaDialog} from "./editPassword.js";

const categoriaDiv = document.getElementById("categories-div")
const searchBar = document.getElementById("searchBar")
const buttonClear = document.getElementById("searchBarClear")
jQuery('#searchBar').keypress(function(event)
{
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if(keycode == '13'){
        categoriaDiv.innerHTML = ""
        loadIndex()
    }
});
buttonClear.onclick = function (e)
{
    categoriaDiv.innerHTML = ""
    loadIndex()
}

loadIndex()

export function loadIndex()
{
    $.get("/categorias", { search: searchBar.value }, (data, status) =>
    {
        if (data !== undefined)
        {
            searchBar.value = ""
            $.get("/senhas", function (dataS, status)
            {
                if (dataS && status === "success")
                {
                    data.forEach(cat =>
                    {
                        let senhas = dataS.filter(e =>
                        {
                            return e.categoria.toString() === cat._id.toString()
                        })

                        let categoria = document.createElement("div")
                        categoria.classList.add("category")
                        categoria.classList.add("noselect")

                        let nome = document.createElement("h5")
                        nome.disabled = true
                        nome.innerHTML = cat.nome

                        let expandIcon = document.createElement("img")
                        expandIcon.src = "/img/expand_more_black24dp.png"

                        let nomediv = document.createElement("div")
                        nomediv.appendChild(nome)
                        nomediv.appendChild(expandIcon)
                        nomediv.style = "padding-top: 5.8px; padding-bottom: 3px;"

                        let botaoDiv = document.createElement("div")
                        botaoDiv.style = "margin-top: -4px; margin-left: 6px;" +
                            "display: flex; flex-direction: row; align-items: center;" +
                            "justify-content: space-around;"

                        let botaoAdd = document.createElement("button")
                        botaoAdd.classList.add("btn-transparent-medium")
                        botaoAdd.classList.add("ripple")
                        botaoAdd.innerHTML = "<img src='img/add_block_black24dp.png' alt='icon'>"
                        botaoAdd["data-toggle"] = "tooltip"
                        botaoAdd.title = "Adicionar nova senha"

                        let botaoEditar = document.createElement("button")
                        botaoEditar.classList.add("btn-transparent-medium")
                        botaoEditar.classList.add("ripple")
                        botaoEditar.innerHTML = "<img src='img/edit_black24dp.png' alt='icon'>"
                        botaoEditar["data-toggle"] = "tooltip"
                        botaoEditar.title = "Editar categoria"

                        let botaoExcluir = document.createElement("button")
                        botaoExcluir.classList.add("btn-transparent-medium")
                        botaoExcluir.classList.add("ripple")
                        botaoExcluir.innerHTML = "<img src='img/delete_black24dp.png' alt='icon'>"
                        botaoExcluir["data-toggle"] = "tooltip"
                        botaoExcluir.title = "Excluir categoria"

                        botaoDiv.appendChild(botaoAdd)
                        botaoDiv.appendChild(botaoEditar)
                        botaoDiv.appendChild(botaoExcluir)

                        let divCima = document.createElement("div")
                        divCima.style = "display: flex;" +
                            "flex-direction: row;" +
                            "width: 100%;" +
                            "height: 100%;" +
                            "align-items: center;" +
                            "justify-content: space-between;" +
                            "cursor: pointer;"

                        divCima.appendChild(nomediv)
                        divCima.appendChild(botaoDiv)

                        let divBaixo = document.createElement("div")
                        divBaixo.style = "display: flex;" +
                            "flex-direction: row;" +
                            "flex-wrap: wrap;" +
                            "justify-content: flex-start;" +
                            "width: 100%; height: 100%;" +
                            "margin-left: -11px"
                        divBaixo.onclick = ev => ev.stopPropagation();
                        senhas.forEach(senha =>
                        {
                            let senhadiv = document.createElement("div")
                            senhadiv.classList.add("password")
                            let textoUsuario = document.createElement("h6")
                            textoUsuario.innerHTML = senha.username
                            textoUsuario.style = "width: 100%; word-wrap: break-word;"

                            senhadiv.appendChild(textoUsuario)
                            divBaixo.appendChild(senhadiv)

                            senhadiv.onclick = function (e)
                            {
                                e.stopPropagation()
                                editarSenhaDialog(senha)
                            }
                        })

                        categoria.appendChild(divCima)
                        categoriaDiv.appendChild(categoria)

                        botaoAdd.onclick = (e) =>
                        {
                            e.stopPropagation()
                            newPasswordDialog(cat)
                        }

                        botaoExcluir.onclick = (e) =>
                        {
                            e.stopPropagation()
                            dialogoExcluir(cat)
                        }

                        botaoEditar.onclick = (e) =>
                        {
                            e.stopPropagation()
                            editarCategoriaDialog(cat)
                        }

                        var categoriaAberta = false
                        categoria.onclick = (e) =>
                        {
                            if (categoriaAberta)
                            {
                                expandIcon.src = "/img/expand_more_black24dp.png"

                                categoria.removeChild(divBaixo)
                            }
                            else
                            {
                                expandIcon.src = "/img/expand_less_black24dp.png"

                                categoria.appendChild(divBaixo)
                            }
                            categoriaAberta = !categoriaAberta
                        }
                    })
                }
            })
        }
    })
}