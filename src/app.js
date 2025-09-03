import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import db from './db.js';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

const app = express();

const HEADER_COMPANY_TOKEN = 'x-token-empresa';
const HEADER_AUTHORIZATION = 'Authorization';
const AUTH_SCHEME = 'Bearer ';

const {
    PARTNER_TOKEN,
    EDEN_HMAC_SECRET,
    ADMIN_URL,
    PORT,
} = process.env;

async function findUserByEmail(email) {
    return db.find(user => user["Email principal"] === email);
}

const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Muitas tentativas de autenticação a partir deste IP. Tente novamente após 1 minuto.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.get('/api/auth/eden-sso', authLimiter, async (req, res) => {
    try {
        const companyToken = req.get(HEADER_COMPANY_TOKEN);
        const authHeader = req.get(HEADER_AUTHORIZATION) || '';
        
        if (!companyToken || !authHeader.startsWith(AUTH_SCHEME)) {
            return res.status(400).json({ error: 'Cabeçalhos de autenticação ausentes ou mal formatados.' });
        }
        
        const partnerToken = authHeader.slice(AUTH_SCHEME.length);
        const partnerTokenBuffer = Buffer.from(PARTNER_TOKEN, 'utf8');
        const receivedTokenBuffer = Buffer.from(partnerToken, 'utf8');
        
        if (partnerTokenBuffer.length !== receivedTokenBuffer.length || 
            !crypto.timingSafeEqual(partnerTokenBuffer, receivedTokenBuffer)) {
            return res.status(401).json({ error: 'Token de parceiro inválido.' });
        }

        let decoded;
        try {
            decoded = jwt.verify(companyToken, EDEN_HMAC_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            console.error('Falha na verificação do JWT:', err.message);
            return res.status(401).json({ error: 'Token da empresa inválido ou expirado.' });
        }
        
        const { email } = decoded;
        if (!email) {
            return res.status(400).json({ error: 'JWT não contém o campo de e-mail.' });
        }
        
        const user = await findUserByEmail(email);

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const adminLink = `${ADMIN_URL}/${email}`;
        console.log(`Link do admin gerado: ${adminLink}`);
        return res.status(200).json({ adminLink });

    } catch (error) {
        console.error('Erro inesperado no endpoint eden-sso:', error);
        return res.status(500).json({ error: 'Ocorreu um erro interno no servidor.' });
    }
});

const serverPort = PORT || 3000;
app.listen(serverPort, () => {
    console.log(`Servidor rodando na porta ${serverPort}`);
});