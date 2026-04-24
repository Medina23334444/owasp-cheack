const express = require('express');
const expressRateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt'); // [SEGURIDAD] Cambiamos crypto por bcrypt
const { v4: uuidv4 } = require('uuid');
const pg = require('pg');
const router = express.Router();

module.exports = function (httpRequestsTotal, dbConfig) {
    const limiter = expressRateLimit({
        windowMs: 1000 * 60 * 60 * 24, // 1 day
        max: 5, 
        handler: (req, res) => {
            console.log(`Too many requests from this IP: ${req.ip}`);
            httpRequestsTotal.inc({ endpoint: 'auth', method: req.method, status_code: '429'});
            res.status(429).json({error: 'Too many requests from this IP, please try again after 24 hours'});
        }
    });

    router.post('/login', limiter, async (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) {
            httpRequestsTotal.inc({ endpoint: 'login', method: 'POST', status_code: '400'});
            res.status(400).json({error: 'Username and password are required'});
            return;
        }

        try {
            const db = new pg.Client(dbConfig);
            await db.connect();
            
            const result = await db.query(`
                SELECT u.id, u.username, u.password, r.role_name
                FROM users u
                JOIN user_roles ur ON u.id = ur.user_id
                JOIN roles r ON ur.role_id = r.id
                WHERE u.username = $1;
            `, [username]);

            if (result.rowCount === 0) {
                await db.end();
                httpRequestsTotal.inc({ endpoint: 'login', method: 'POST', status_code: '401'});
                res.status(401).json({error: 'Invalid username'});
                return;
            }

            const user = result.rows[0];
            await db.end();

            // [SEGURIDAD] Comparación segura con bcrypt
            const esValida = await bcrypt.compare(password, user.password);

            if (!esValida) {
                httpRequestsTotal.inc({ endpoint: 'login', method: 'POST', status_code: '401'});
                res.status(401).json({error: 'Invalid password'});
                return;
            }

            const session = { sid: uuidv4(), userId: user.id, role: user.role_name };
            const sessionEncoded = Buffer.from(JSON.stringify(session), 'ascii').toString('base64');

            res.cookie('main_session', sessionEncoded, {
                httpOnly: false,
                secure: true,
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 * 24 * 30
            });
            httpRequestsTotal.inc({ endpoint: 'login', method: 'POST', status_code: '200'});
            res.json({message: 'Login successful' });
        } catch (err) {
            console.error(err);
            httpRequestsTotal.inc({ endpoint: 'login', method: 'POST', status_code: '500'});
            res.status(500).json({error: 'Internal server error'});
        }
    });

    router.get('/logout', async (req, res) => {
        res.clearCookie('main_session');
        httpRequestsTotal.inc({ endpoint: 'logout', method: 'GET', status_code: '200'});
        res.json({message: 'Logout successful'});
    });

    router.post('/register', async (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) {
            httpRequestsTotal.inc({ endpoint: 'register', method: 'POST', status_code: '400'});
            res.status(400).json({error: 'Username, password are required'});
            return;
        }

        // [SEGURIDAD] Hashing con bcrypt (factor de trabajo 10)
        const hashedPassword = await bcrypt.hash(password, 10);

        try {
            const db = new pg.Client(dbConfig);
            await db.connect();
            const result = await db.query(`
                INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id;
            `, [username, hashedPassword]);
            
            const userId = result.rows[0].id;
            await db.query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, 2);`, [userId]);
            
            await db.end();
            httpRequestsTotal.inc({ endpoint: 'register', method: 'POST', status_code: '200'});
            res.json({message: 'Registration successful'});
        } catch (err) {
            console.error(err);
            httpRequestsTotal.inc({ endpoint: 'register', method: 'POST', status_code: '500'});
            res.status(500).json({error: 'Internal server error'});
        }
    });

    return router;
};
