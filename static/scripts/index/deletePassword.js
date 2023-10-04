function deletarSenhaDialog(senha)
{
    let dialog = new duDialog("Confirme sua escolha", "Deseja realmente deletar essa senha?",
    {
        buttons: duDialog.OK_CANCEL,
        okText: "Confirmar",
        cancelText: "Cancelar",
        callbacks:{
            cancelClick: function (e)
            {
                $.ajax("/senhas",
                    {
                        type: "DELETE",
                        data:JSON.stringify({
                            senhaID: senha
                        }),
                        contentType: "application/json; charset=utf-8",
                        statusCode: {
                            200: function (response)
                            {
                                dialog.hide()
                                new duDialog("Sucesso", "Senha excluida com sucesso!",
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
                                dialog.hide()
                                new duDialog("Erro", "Houve um problema ao excluir sua senha, tente novamente mais tarde.")
                            },
                            400: function (response)
                            {
                                dialog.hide()
                                new duDialog("Erro", "Entrada(s) inseridas inválidas.")
                            },
                            403: function (response)
                            {
                                dialog.hide()
                                new duDialog("Erro", "Senha incorreta, tente novamente.")
                            }
                        }
                    }
                )
            }
        }
    })
}