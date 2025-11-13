// comando executado primeiro: npm i express mysql2 express-session crypto
const express = require('express')
const mysql = require('mysql2/promise')
const crypto = require('crypto')
const session = require('express-session') // importa express-session

// configuração do banco de dados
const conn = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "escola"
})

const app = express()
const PORT = 3001 // porta unificada



// configurar para ler json no corpo das requisições
app.use(express.json())
// configurar para ler dados de formulário (necessário para o html de login)
app.use(express.urlencoded({ extended: true }))

// configurar a sessão do usuário
app.use(session({
    secret: 'aee0aac0fbc8ee8170795704c99bfbf2ffb8d9a351eef9a2db39a80cd0b65e48', //Senha Secreta SHA256
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 600000 } // exemplo: 10 minutos de duração (em milissegundos)
}))

// define a pasta estática para servir os arquivos do frontend (index.html e login.html)
// o caminho foi ajustado para 'frontend'
app.use(express.static('frontend'));


//rotas 

// rota de documentação 

app.get("/", (req, res) => {
    // verifica se o usuário está logado
    if (req.session.usuario) {
        // se estiver logado, envia o arquivo index.html (da pasta frontend)
        res.sendFile(__dirname + '/frontend/index.html');
    } else {
        // se não estiver logado, redireciona para o login
        res.redirect('/login');
    }
})

// rota de login (get /login)

app.get('/login', (req, res) => {
    // se o usuário já estiver logado, redireciona para a página principal
    if (req.session.usuario) {
        return res.redirect('/');
    }
    // envia o arquivo login.html (da pasta frontend)
    res.sendFile(__dirname + '/frontend/login.html');
});

// rota de autenticação (post /login)

app.post("/login", async (req, res) => {
    const { usuario, senha } = req.body // recebe usuário e senha do corpo da requisição

    if (!usuario || !senha) {
        return res.status(400).send('usuário e senha são obrigatórios.');
    }

    // criptografa a senha com hash sha256
    const senha_hash = crypto.createHash("sha256").update(senha, "utf-8").digest("hex")

    const sql = "select nome_usuario from usuarios_login where nome_usuario = ? and senha_hash = ?;"

    const ip_usuario = req.ip // obtendo o ip do usuário

    try {
        // executa a consulta no banco de dados
        const [rows] = await conn.query(sql, [usuario, senha_hash])

        //  log de consulta 
        const logSql = `INSERT INTO log (data_hora, sql_executado, ip_usuario, parametros, resultado) 
                         VALUES (utc_timestamp(), ?, ?, ?, ?)`
        const parametros = JSON.stringify({ usuario, senha_hash })
        const resultado = rows.length > 0 ? 'y' : 'n' // y=sucesso, n=falha
        
        await conn.query(logSql, [sql, ip_usuario, parametros, resultado])

        // verificação de login
        if (rows.length > 0) {
            // login bem-sucedido: cria a sessão do usuário
            req.session.usuario = rows[0].nome_usuario;
            // redireciona para a página principal
            res.redirect('/'); 
        } else {
            // login falhou
            res.send('usuário ou senha inválidos. <a href="/login">tente novamente</a>');
        }

    } catch (error) {
        console.error('erro ao processar login:', error)
        res.status(500).json({
            msg: "erro interno do servidor"
        })
    }
})

// rota de logout 

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('erro ao encerrar a sessão:', err);
            return res.redirect('/');
        }
        res.clearCookie('connect.sid'); // limpa o cookie de sessão (nome padrão)
        res.redirect('/login');
    });
});

// rota de logout (POST, precisa ter um post e um get para funcionar o formulário)
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('erro ao encerrar a sessão:', err);
            return res.status(500).send('Erro ao encerrar a sessão.');
        }
        res.clearCookie('connect.sid'); // limpa o cookie de sessão (nome padrão)
        res.redirect('/login');
    });
});

// rota para cadastrar um novo usuário
app.post('/usuarios', async (req, res) => {
    const { usuario, senha } = req.body; // recebe os dados do corpo da requisição

    if (!usuario || !senha) {
        return res.status(400).send('Usuário e senha são obrigatórios.');
    }

    // criptografa a senha com hash sha256 (igual antes)
    const senha_hash = crypto.createHash('sha256').update(senha, 'utf-8').digest('hex');
    const sql = 'INSERT INTO usuarios_login (nome_usuario, senha_hash) VALUES (?, ?)';

    try {
        // insere o novo usuário no banco de dados
        await conn.query(sql, [usuario, senha_hash]);
        res.status(201).send('Usuário cadastrado com sucesso!');
    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
    }
});

app.listen(PORT, () => console.log(`servidor rodando em http://localhost:${PORT}`))