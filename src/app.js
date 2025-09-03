import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PARTNER_TOKEN = process.env.PARTNER_TOKEN;
const EDEN_HMAC_SECRET = process.env.EDEN_HMAC_SECRET;
const PORT = process.env.PORT;

app.get('/api/auth/eden-sso', (req, res) => {
    const email = req.query.email;
    const token = req.query.token;
    const jwtToken = req.get('x-token-empresa');
    const auth = req.get('Authorization') || '';
    const partnerToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';

    if (!email || !token) {
        return res.status(400).json({ error: 'Parâmetros insuficientes' });
    }
    
    if (partnerToken != PARTNER_TOKEN) {
        return res.status(401).json({ error: 'Invalid partner token' });
    }
    
    if (!jwtToken) return res.status(400).json({ error: 'x-token-empresa ausente' });

    let decoded;
    try {
        decoded = jwt.verify(jwtToken, EDEN_HMAC_SECRET, { algorithms: ['HS256'] });
    } catch(err) {
        return res.status(401).json({ error: err.message });
    }

    if (email !== decoded.email) {
        return res.status(401).json({ error: 'E-mail difere do JWT' });
    }

    // Lógica para verificar se o usuário existe na base de dados
    // Se não existir, retornar erro 400 (usuário não encontrado)
    // Se existir, gerar link de login

    const link_admin = `${process.env.ADMIN_URL}/${decoded.email}`;
    return res.status(200).json({ link_admin });
});

app.listen(PORT, () => {
  console.log(`Rodando na porta ${PORT}`);
});

export default app;