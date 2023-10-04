export function editarSenhaDialog(senha)
{
    let senhaDialog = new duDialog("Confirmar identidade",
        [
            {name:"Insira a senha da sua<br>conta: ", type: "password", placeholder: "Senha", id:"senhaContaVisualizarSenha"}
        ],
        {
            selection: true, multiple: true,
            buttons: 2,
            textField: 'name',
            valueField: 'id',
            minSelect: 0,
            okText: "Confirmar",
            cancelText: "Cancelar",
            callbacks: {
                // i - array of selected items (string or object)
                itemSelect: function (e, i)
                {
                    // this.value - value array of the selected items; in this case array of fruit 'id'
                },
                itemRender: function (i)
                {
                    return "<div style='display: flex; flex-direction: column; align-items: flex-start; margin: 10px 0 10px -20px;'>" +
                        "<p style='margin-bottom: 2px'>" + i.name + "</p>" +
                        "<input id='" + i.id + "' type='" + i.type + "' placeholder='" + i.placeholder + "'>" +
                        "</div>";
                },
                okClick: function (e)
                {
                },
                cancelClick: function (e)
                {
                    let senhaInput = document.getElementById("senhaContaVisualizarSenha")
                    let decrypted = CryptoJS.AES.decrypt(senha.senha_cript, senhaInput.value)
                    if (decrypted.sigBytes < 0)
                    {
                        new duDialog("Erro", "Senha incorreta.")
                    } else
                    {
                        senhaDialog.hide()

                        let dialog = new duDialog("Editar e Visualizar Senha",
                            [
                                {
                                    name: "Descrição da senha: ",
                                    type: "text",
                                    placeholder: "Descrição",
                                    id: "senhaInputDescricao",
                                    value: senha.descricao
                                },
                                {
                                    name: "Nome de usuário<br>relacionado à senha: ",
                                    type: "text",
                                    placeholder: "Nome de usuário",
                                    id: "senhaInputUsuario",
                                    value: senha.username
                                },
                                {
                                    name: "Senha guardada: ",
                                    type: "text",
                                    placeholder: "Senha",
                                    id: "senhaInputSenha",
                                    value: decrypted.toString(CryptoJS.enc.Utf8)
                                },
                                {
                                    name: "Excluir essa senha",
                                    button: true,
                                    id: "excluirSenhaButton",
                                    icon: "/img/delete_black24dp.png"
                                }
                            ],
                            {
                                selection: true, multiple: true,
                                buttons: 2,
                                textField: 'name',
                                valueField: 'id',
                                minSelect: 0,
                                okText: "Confirmar",
                                cancelText: "Cancelar",
                                callbacks: {
                                    itemSelect: function (e, i)
                                    {
                                    },
                                    itemRender: function (i)
                                    {
                                        if (i.button)
                                        {
                                            return "<div id='" + i.id + "' style='display: flex; flex-direction: row; justify-content: space-between; height: 50px; align-items: center;' onclick='deletarSenhaDialog(\"" + senha._id + "\")'>" +
                                                "<span style='margin: 0 10px 0 -10px;'>" + i.name + "</span>" +
                                                "<img style='max-height: 24px; max-width: 24px;' src='" + i.icon + "'>" +
                                                "</div>"
                                        }
                                        else
                                        {
                                            return "<div style='display: flex; flex-direction: column; align-items: flex-start; margin: 10px 0 10px -20px;'>" +
                                                "<p style='margin-bottom: 2px'>" + i.name + "</p>" +
                                                "<input id='" + i.id + "' type='" + i.type + "' placeholder='" + i.placeholder + "' value='" + i.value + "'>" +
                                                "</div>";
                                        }
                                    },
                                    okClick: function (e)
                                    {
                                    },
                                    cancelClick: function (e)
                                    {
                                        let descricao = document.getElementById("senhaInputDescricao")
                                        let usuario = document.getElementById("senhaInputUsuario")
                                        let senhaInputSenha = document.getElementById("senhaInputSenha")
                                        let senhaConta = senhaInput.value
                                        let senhaID = senha._id

                                        $.ajax("/senhas",
                                            {
                                                type: "PUT",
                                                data:JSON.stringify({
                                                    descricao: descricao.value,
                                                    username: usuario.value,
                                                    senha_cript: senhaInputSenha.value,
                                                    senha: senhaConta,
                                                    senhaID: senhaID
                                                }),
                                                contentType: "application/json; charset=utf-8",
                                                statusCode: {
                                                    200: function (response)
                                                    {
                                                        new duDialog("Sucesso", "Senha editada com sucesso!",
                                                            {
                                                                callbacks:{
                                                                    cancelClick: function (e)
                                                                    {
                                                                        dialog.hide()
                                                                        location.reload()
                                                                    }
                                                                }
                                                            })
                                                    },
                                                    500: function (response)
                                                    {
                                                        new duDialog("Erro", "Houve um problema ao editar sua senha, tente novamente mais tarde.")
                                                    },
                                                    400: function (response)
                                                    {
                                                        new duDialog("Erro", "Entrada(s) inseridas inválidas.")
                                                    },
                                                    403: function (response)
                                                    {
                                                        new duDialog("Erro", "Senha incorreta, tente novamente.")
                                                    }
                                                }
                                            }
                                        )
                                    }
                                }
                            })
                    }
                }
            }
        })
}