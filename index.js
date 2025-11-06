//comando executado primeiro --> npm i express, que é usado para criar as dependencias do servidor

const express = require('express')
const mysql = require('mysql2/promise')
const crypto = require('crypto') //importa a biblioteca crypto, que vai ser usado para criptografar a senha com o "hash" 

const conn = mysql.createPool({ //aqui estamos importando as configurações do banco de dados (as que aparecem quando iniciamos o heidi)
    host:"localhost", 
    user:"root",
    password: "",
    database: "escola"
})

const app = express()
app.use(express.json())

const PORT = 3001//aqui definimos a porta do servidor de um jeito diferente
app.listen(PORT)

app.get("/", (req, res) => { //Isso define uma rota de acesso raiz ""("/")"""que responde a requisições GET
    res.json({
        rotas: {
            "/":"GET- Obtém todas as rotas disponíveis", //colocar todas as rotas aqui embaixo. / vai ser a rota de documentação, colocar a rota, o metodo e o que ele faz
            "/login":"POST - Recebe usuario para autenticar"
        }
    })
})

app.post("/login", async (req, res) => {
    const {usuario, senha} = req.body //assim é que recebe o usuário, assim que obtem o usuario, senha, etc, com isso {} e as virgulas, da para obter varios valores

    // altera de senha para crypto
    const senha_hash = crypto.createHash("sha256").update(senha,"utf-8").digest("hex")

    const sql = "select * from usuarios_login where nome_usuario = ? and senha_hash = ?;";//comando dentro do sql 

    //cria uma ação momentanea que manipula sql, e dentro do sql o usuario e o hash
    const ip_usuario = req.ip // Obtendo o IP do usuário

    try {
        // executa a consulta no banco de dados
        const [rows] = await conn.query(sql, [usuario, senha_hash]) //estamos dizendo para a variavel conexao executar a variavel sql

        // eegistra o log de consulta no banco de dados
        const logSql = `INSERT INTO log (data_hora, sql_executado, ip_usuario, parametros, resultado) 
                        VALUES (UTC_TIMESTAMP(), ?, ?, ?, ?)` // utilizando UTC_TIMESTAMP() para garantir a data/hora no formato UTC

        const parametros = JSON.stringify({ usuario, senha_hash }) // são os parametros passados para a consulta sql

        const resultado = rows.length > 0 ? 'Y' : 'N' // Y significa que o login foi bem sucedido, N significa que falhou (Está assim pois defini o resultado como ENUM no HEIDI)
        
        await conn.query(logSql, [sql, ip_usuario, parametros, resultado]) // Inserindo as instruções do sql na tabela log


        // verificação se existe
        if(rows.length > 0){
            res.json({
                Msg: "Existe", usuario: rows[0]//aqui ele retorna o usuario que foi encontrado no banco de dados
            })

        } else {
            res.json({ //resposta do json que aparece quando o usuario ou senha estão incorretos
                Msg: "Usuario ou senha incorreta" 
            })
        }


    } catch (error) {//catch vai capturar qualquer erro que ocorrer dentro do bloco try lá em cima
        console.error('Erro ao processar login:', error)//mostra o erro no console
        res.status(500).json({
            Msg: "Erro interno do servidor"
        })
    }


})
