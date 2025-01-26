require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const sql = require("mssql");
const bcrypt = require("bcryptjs");

const sqlConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER, 
    database: process.env.DB_NAME,
    options: {
        trustServerCertificate: true,
        encrypt: false
    }
};

const app = express();
app.use(bodyParser.json());

// Home endpoint
app.get("/", (req, res) => {
    res.json({
        status: "online",
        message: "Database Server is running"
    });
});

// Check Connection Endpoint
app.get('/check', async (req, res) => {
    try {
        await sql.connect(sqlConfig);
        res.status(200).json({ 
            status: 'Connected', 
            message: 'Database connection successful' 
        });
    } catch (err) {
        res.status(500).json({ 
            status: 'Failed', 
            message: 'Database connection error',
            error: err.message 
        });
    } finally {
        await sql.close();
    }
});

// Signup endpoint (similar to previous implementation)
app.post("/signup", async (req, res) => {
    const { username, email, password, firstname, lastname, age, gender, mobilenumber } = req.body;

    try {
        await sql.connect(sqlConfig);
        const transaction = new sql.Transaction();
        await transaction.begin();

        try {
            // Check if user already exists
            const existingUser = await transaction.request()
                .input('username', sql.NVarChar, username)
                .input('email', sql.NVarChar, email)
                .query('SELECT * FROM users WHERE username = @username OR email = @email');
            
            if (existingUser.recordset.length > 0) {
                return res.status(400).json({ message: "Username or email already exists" });
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Insert user
            const userResult = await transaction.request()
                .input('username', sql.NVarChar, username)
                .input('email', sql.NVarChar, email)
                .input('password', sql.NVarChar, hashedPassword)
                .query('INSERT INTO users (username, email, password) VALUES (@username, @email, @password); SELECT SCOPE_IDENTITY() AS user_id;');
            
            const userId = userResult.recordset[0].user_id;
            
            // Insert user profile
            await transaction.request()
                .input('user_id', sql.Int, userId)
                .input('firstname', sql.NVarChar, firstname)
                .input('lastname', sql.NVarChar, lastname)
                .input('age', sql.Int, age ? parseInt(age, 10) : null)
                .input('gender', sql.NVarChar, gender)
                .input('mobile_number', sql.NVarChar, mobilenumber)
                .query('INSERT INTO user_profile (user_id, firstname, lastname, age, gender, mobile_number) VALUES (@user_id, @firstname, @lastname, @age, @gender, @mobile_number)');

            await transaction.commit();
            res.status(201).json({ message: "User registered successfully", userId });
        } catch (insertError) {
            await transaction.rollback();
            throw insertError;
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error during registration" });
    } finally {
        await sql.close();
    }
});

// Login endpoint (similar to previous implementation)
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        await sql.connect(sqlConfig);
        const result = await sql.query`
            SELECT * FROM users 
            WHERE username = ${username}`;
        
        if (result.recordset.length === 0) {
            return res.status(400).json({ message: "User not found" });
        }
        
        const user = result.recordset[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }
        
        res.json({ 
            message: "Login successful", 
            user: { 
                id: user.user_id, 
                username: user.username 
            } 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    } finally {
        await sql.close();
    }
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});