const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs'); // MODIFICADO: Versão leve ideal para rodar no celular
const path = require('path');
const cors = require('cors'); // MODIFICADO: Liberar o acesso para o APK Android conectar

const app = express();
const PORT = process.env.PORT || 3000; // MODIFICADO: Porta flexível para servidores em nuvem

// MODIFICADO: Ativando a liberação de segurança CORS
app.use(cors()); 

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Inicializa o Banco de Dados SQLite
const db = new sqlite3.Database('./usuarios.db', (err) => {
    if (err) console.error('Erro no banco de dados:', err.message);
});

// Cria a tabela de usuários de forma segura
db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// ROTA DE CADASTRO (Retorna respostas em formato JSON amigável para APKs)
app.post('/api/cadastro', async (req, res) => {
    const { email, username, password, 'confirm-password': confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'As senhas não coincidem!' });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const sql = `INSERT INTO usuarios (email, username, password) VALUES (?, ?, ?)`;
        
        db.run(sql, [email, username, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'E-mail ou Usuário já cadastrado.' });
                }
                return res.status(500).json({ error: 'Erro ao salvar os dados no banco.' });
            }
            res.status(201).json({ success: true, message: 'Usuário cadastrado com sucesso!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno no servidor.' });
    }
});

// ROTA DE LOGIN (Retorna respostas em formato JSON amigável para APKs)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM usuarios WHERE username = ?`;
    
    db.get(sql, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor.' });
        if (!user) return res.status(400).json({ error: 'Usuário ou senha incorretos.' });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            res.json({ success: true, username: user.username, message: 'Login realizado!' });
        } else {
            res.status(400).json({ error: 'Usuário ou senha incorretos.' });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando com sucesso!`);
});
         
