// server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// Mock Database (In-memory user data for simplicity)
const users = [
    {
        username: 'admin',
        password: bcrypt.hashSync('admin123', 10), // Hashed password
        role: 'admin'
    },
    {
        username: 'user',
        password: bcrypt.hashSync('user123', 10),
        role: 'user'
    }
];

// Middleware: Verify JWT Token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
}

// Middleware: Role-Based Access Control
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Access Denied' });
        }
        next();
    };
}

// User Login (Authentication)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid Credentials' });
    }

    // Generate JWT Token
    const token = jwt.sign(
        { username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({ token });
});

// Protected Route (Accessible to All Authenticated Users)
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ message: `Welcome, ${req.user.username}`, role: req.user.role });
});

// Admin-Only Route
app.get('/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
    res.json({ message: 'Welcome Admin! This is a restricted route.' });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
