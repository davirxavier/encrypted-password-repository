export function newPasswordDialog (categoria)
{
    const dialog = new duDialog("Nova Senha",
        [
            {name: "Insira uma descrição para<br>essa senha: ", type: "text", placeholder: "Descrição da senha", id: "senhaInputDescricao"},
            {name: "Insira um nome de usuário<br>relacionado à essa senha: ", type: "text", placeholder: "Nome de usuário", id:"senhaInputUsuario"},
            {name: "Insira a senha à ser guardada: ", type: "text", placeholder: "Senha", id: "senhaInputSenha"},
            {name: "Insira a senha da sua conta: ", type: "password", placeholder: "Senha da conta", id: "senhaInputSenhaConta"}
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
                itemSelect: function(e, i)
                {
                    // this.value - value array of the selected items; in this case array of fruit 'id'
                },
                itemRender: function(i)
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
                    let descricao = document.getElementById("senhaInputDescricao")
                    let username = document.getElementById("senhaInputUsuario")
                    let senha_cript = document.getElementById("senhaInputSenha")
                    let senha = document.getElementById("senhaInputSenhaConta")

                    $.ajax("/senhas",
                        {
                            type: "POST",
                            data:JSON.stringify({
                                descricao: descricao.value,
                                username: username.value,
                                senha_cript: senha_cript.value,
                                senha: senha.value,
                                categoria: categoria._id
                            }),
                            contentType: "application/json; charset=utf-8",
                            statusCode: {
                                200: function (response)
                                {
                                    new duDialog("Sucesso", "Senha adicionada com sucesso!",
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
                                    new duDialog("Erro", "Houve um problema ao adicionar sua senha, tente novamente mais tarde.")
                                },
                                400: function (response)
                                {
                                    new duDialog("Erro", "Entrada(s) inválida(s).")
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