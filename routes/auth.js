const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
require('dotenv').config();

const router = express.Router();

// Register Route
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if email already exists
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: "Email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into database
        const newUser = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *',
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: "User registered successfully", user: newUser.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login Route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (user.rows.length === 0) return res.status(400).json({ error: "User not found" });

        // Compare password
        const isMatch = await bcrypt.compare(password, user.rows[0].password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

        // Generate JWT Token
        const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ Temporary Blacklist (Resets on Server Restart)
let blacklistedTokens = [];

// ✅ Middleware to Verify JWT and Check If Blacklisted
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

    // ❌ Check if Token is Blacklisted
    if (blacklistedTokens.includes(token)) {
        return res.status(403).json({ message: "Token is blacklisted. Please log in again." });
    }

    // ✅ Verify Token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token." });

        req.user = user;
        next();
    });
};

// ✅ Logout Route (Blacklist Token)
router.post("/logout", (req, res) => {
    const token = req.body.token;

    if (!token) {
        return res.status(400).json({ message: "Token required for logout" });
    }

    blacklistedTokens.push(token);
    res.json({ message: "Logged out successfully" });
});


// ✅ Protected Route: Dashboard
router.get("/dashboard", authenticateToken, async (req, res) => {
    try {
        // Fetch user details from DB
        const user = await pool.query("SELECT id, email FROM users WHERE id = $1", [req.user.id]);

        if (user.rows.length === 0) return res.status(404).json({ message: "User not found." });

        res.json({ message: "Welcome to your dashboard!", user: user.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
