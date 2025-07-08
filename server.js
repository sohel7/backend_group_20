// Load environment variables
require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db'); // MySQL connection

const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

// ----------------- Register Route -----------------
app.post('/register', async (req, res) => {
    const { name, email, phone, address, password, image } = req.body;

    // Check if the user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into the database
        db.query(
            'INSERT INTO users (name, email, phone, address, password, image) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, phone, address, hashedPassword, image],
            (err) => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Failed to register user' });
                }
                return res.status(201).json({ success: true, message: 'User registered successfully' });
            }
        );
    });
});


// ----------------- Login Route -----------------
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = results[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).json({ message: 'Invalid email or password' });

        const token = jwt.sign({ email: user.email, userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login successful', token });
    });
});

// ----------------- Middleware: Authenticate Token -----------------
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']; // "Bearer TOKEN"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });

        req.user = user;
        next();
    });
}

// ----------------- Protected Route: Add Deposit -----------------
app.post('/deposit', authenticateToken, (req, res) => {
    const { month, amount } = req.body;
    const userEmail = req.user.email;

    db.query('SELECT id FROM users WHERE email = ?', [userEmail], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }

        const userId = results[0].id;

        db.query(
            'INSERT INTO deposits (user_id, month, amount, creation_date, status) VALUES (?, ?, ?, CURDATE(), ?)',
            [userId, month, amount, 'Pending'],
            (err) => {
                if (err) return res.status(500).json({ message: 'Failed to add deposit' });
                res.status(201).json({ message: 'Deposit added successfully' });
            }
        );
    });
});

// ----------------- Default Home Route -----------------
app.get('/', (req, res) => {
    res.send('Group 20 Backend is running!');
});

//app.listen(port, () => {
//    console.log(`Server listening on http://localhost:${port}`);
// });

app.listen(3000, () => {
    console.log("Server listening on http://localhost:3000");
});

