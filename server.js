const express = require("express");
const bodyParser = require("body-parser");
const { Connection, Request } = require('tedious');
const { Connector } = require('@google-cloud/cloud-sql-connector');
const bcrypt = require("bcryptjs");

let connector;
let connection;

async function initializeDatabase() {
    connector = new Connector();
    const clientOpts = await connector.getTediousOptions({
        instanceConnectionName: 'adept-shade-448605-u0:asia-southeast1:pal-ai',
        ipType: 'PUBLIC',
    });

    connection = new Connection({
        server: '0.0.0.0', // Note: This is due to a tedious driver bug
        authentication: {
            type: 'default',
            options: {
                userName: process.env.DB_USER,
                password: process.env.DB_PASSWORD,
            },
        },
        options: {
            ...clientOpts,
            port: 9999, // Note: This is due to a tedious driver bug
            database: process.env.DB_NAME,
        },
    });

    return new Promise((resolve, reject) => {
        connection.connect(err => {
            if (err) {
                reject(err);
            } else {
                resolve(connection);
            }
        });
    });
}

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
        const request = new Request('SELECT GETUTCDATE()', (err) => {
            if (err) {
                throw err;
            }
        });

        request.on('requestCompleted', () => {
            res.status(200).json({ 
                status: 'Connected', 
                message: 'Database connection successful' 
            });
        });

        connection.execSql(request);
    } catch (err) {
        res.status(500).json({ 
            status: 'Failed', 
            message: 'Database connection error',
            error: err.message 
        });
    }
});

// Signup endpoint
app.post("/signup", async (req, res) => {
    const { username, email, password, firstname, lastname, age, gender, mobilenumber } = req.body;

    try {
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Begin a transaction
        const request = new Request(`
            BEGIN TRANSACTION;
            
            -- Check if user exists
            DECLARE @existingUser INT;
            SELECT @existingUser = COUNT(*) FROM users 
            WHERE username = @username OR email = @email;
            
            IF @existingUser = 0
            BEGIN
                -- Insert user
                INSERT INTO users (username, email, password) 
                VALUES (@username, @email, @hashedPassword);
                
                DECLARE @userId INT = SCOPE_IDENTITY();
                
                -- Insert user profile
                INSERT INTO user_profile (user_id, firstname, lastname, age, gender, mobile_number)
                VALUES (@userId, @firstname, @lastname, @age, @gender, @mobilenumber);
                
                COMMIT TRANSACTION;
                SELECT @userId AS user_id;
            END
            ELSE
            BEGIN
                ROLLBACK TRANSACTION;
                SELECT -1 AS user_id;
            END
        `, (err) => {
            if (err) {
                return res.status(500).json({ message: "Server error during registration" });
            }
        });

        request.addParameter('username', TYPES.NVarChar, username);
        request.addParameter('email', TYPES.NVarChar, email);
        request.addParameter('hashedPassword', TYPES.NVarChar, hashedPassword);
        request.addParameter('firstname', TYPES.NVarChar, firstname);
        request.addParameter('lastname', TYPES.NVarChar, lastname);
        request.addParameter('age', TYPES.Int, age ? parseInt(age, 10) : null);
        request.addParameter('gender', TYPES.NVarChar, gender);
        request.addParameter('mobilenumber', TYPES.NVarChar, mobilenumber);

        request.on('row', (columns) => {
            const userId = columns[0].value;
            if (userId === -1) {
                return res.status(400).json({ message: "Username or email already exists" });
            }
            res.status(201).json({ message: "User registered successfully", userId });
        });

        connection.execSql(request);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error during registration" });
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const request = new Request(`
            SELECT * FROM users 
            WHERE username = @username
        `, (err) => {
            if (err) {
                return res.status(500).json({ message: "Server error" });
            }
        });

        request.addParameter('username', TYPES.NVarChar, username);

        let user = null;
        request.on('row', (columns) => {
            user = {
                id: columns.find(col => col.metadata.colName === 'user_id').value,
                username: columns.find(col => col.metadata.colName === 'username').value,
                password: columns.find(col => col.metadata.colName === 'password').value
            };
        });

        request.on('requestCompleted', async () => {
            if (!user) {
                return res.status(400).json({ message: "User not found" });
            }
            
            const isMatch = await bcrypt.compare(password, user.password);
            
            if (!isMatch) {
                return res.status(400).json({ message: "Invalid credentials" });
            }
            
            res.json({ 
                message: "Login successful", 
                user: { 
                    id: user.id, 
                    username: user.username 
                } 
            });
        });

        connection.execSql(request);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Startup function
async function startServer() {
    try {
        await initializeDatabase();
        const PORT = process.env.PORT || 5000;
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    } catch (err) {
        console.error("Failed to connect to database:", err);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', () => {
    if (connection) {
        connection.close();
    }
    if (connector) {
        connector.close();
    }
    process.exit();
});

startServer();