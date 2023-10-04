export function editarCategoriaDialog(categoria)
{
    let dialog = new duDialog("Editar Categoria",
        [
            {name: "Novo nome da categoria: ", type: "text", placeholder: "Nome da categoria", id: "editarCategoriaInputNome"},
            {name: "Insira a senha da sua conta: ", type: "password", placeholder: "Senha da conta", id: "editarCategoriaInputSenha"}
        ],{
            selection: true, multiple: true,
            buttons: 2,
            textField: 'name',
            valueField: 'id',
            minSelect: 0,
            okText: "Confirmar",
            cancelText: "Cancelar",
            callbacks: {
                itemSelect: function(e, i)
                {
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
                    let nome = document.getElementById("editarCategoriaInputNome")
                    let senha = document.getElementById("editarCategoriaInputSenha")

                    $.ajax("/categorias",
                        {
                            type: "PUT",
                            data:JSON.stringify({
                                id: categoria._id,
                                nome: nome.value,
                                senha: senha.value
                            }),
                            contentType: "application/json; charset=utf-8",
                            statusCode: {
                                200: function (response)
                                {
                                    new duDialog("Sucesso", "Categoria editada com sucesso!",
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
                                    new duDialog("Erro", "Houve um problema ao editar sua categoria, tente novamente mais tarde.")
                                },
                                400: function (response)
                                {
                                    new duDialog("Erro", "Nome ou senha inseridos inválidos.")
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