export function dialogoExcluir(categoria)
{
    const dialog = new duDialog("Excluir Categoria",
        [
            {name: "Insira a senha da sua conta: ", type: "password", placeholder: "Senha da conta", id:"categoriaInputSenha"}
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
                    let senha = document.getElementById("categoriaInputSenha")

                    $.ajax("/categorias",
                        {
                            type: "DELETE",
                            data: JSON.stringify({
                                catID: categoria._id,
                                senha: senha.value
                            }),
                            contentType: "application/json; charset=utf-8",
                            statusCode: {
                                200: function (response)
                                {
                                    new duDialog("Sucesso", "Categoria removida com sucesso!",
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
                                    new duDialog("Erro", "Houve um problema ao remover sua categoria, tente novamente mais tarde.")
                                },
                                403: function (response)
                                {
                                    new duDialog("Erro", "Senha incorreta, tente novamente.")
                                }
                            }
                        })
                }
            }
        })
}