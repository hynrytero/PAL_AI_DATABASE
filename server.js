const express = require('express');
const bodyParser = require('body-parser');
const { Connection, Request, TYPES } = require('tedious');
const { Connector } = require('@google-cloud/cloud-sql-connector');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { Storage } = require('@google-cloud/storage');
const multer = require('multer');

// Initialize Google Cloud Storage
const storage = new Storage({
    projectId: process.env.GOOGLE_CLOUD_PROJECT,
});
const bucket = storage.bucket(process.env.BUCKET_NAME);

// Create Express app
const app = express();
app.use(bodyParser.json());

// Database connection setup
let connection;
let connector;

async function initDatabaseConnection() {
    try {
        connector = new Connector();
        const clientOpts = await connector.getTediousOptions({
            instanceConnectionName: process.env.DB_SERVER,
            ipType: 'PUBLIC',
        });

        connection = new Connection({
            server: '0.0.0.0', // Note: this is due to a tedious driver bug
            authentication: {
                type: 'default',
                options: {
                    userName: process.env.DB_USER,
                    password: process.env.DB_PASSWORD,
                },
            },
            options: {
                ...clientOpts,
                port: 9999, // Note: this is due to a tedious driver bug
                database: process.env.DB_NAME,
                trustServerCertificate: true,
                encrypt: false
            },
        });

        connection.on('connect', (err) => {
            if (err) {
                console.error('Database connection failed:', err);
                return;
            }
            console.log('Connected to Cloud SQL database');
        });

        connection.on('error', (err) => {
            console.error('Database connection error:', err);
        });

        connection.connect();
    } catch (error) {
        console.error('Failed to initialize database connection:', error);
    }
}

// Utility function to execute SQL queries
function executeQuery(query, params = []) {
    return new Promise((resolve, reject) => {
        const request = new Request(query, (err) => {
            if (err) {
                reject(err);
            }
        });

        // Add input parameters
        params.forEach((param, index) => {
            request.addParameter(`param${index}`, param.type, param.value);
        });

        const results = [];
        request.on('row', (columns) => {
            results.push(columns);
        });

        request.on('requestCompleted', () => {
            resolve(results);
        });

        request.on('error', (err) => {
            reject(err);
        });

        connection.execSql(request);
    });
}

// Signup endpoint
app.post("/signup", async (req, res) => {
    try {
        const { username, email, password, firstname, lastname, age, gender, mobilenumber } = req.body;

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Start transaction
        const DEFAULT_ROLE_ID = 1;

        try {
            // Insert user credentials
            const userInsertQuery = `
                INSERT INTO user_credentials (username, role_id, password)
                VALUES (@param0, @param1, @param2);
                SELECT SCOPE_IDENTITY() AS userId;
            `;
            const userParams = [
                { type: TYPES.NVarChar, value: username },
                { type: TYPES.Int, value: DEFAULT_ROLE_ID },
                { type: TYPES.NVarChar, value: hashedPassword }
            ];
            const userResult = await executeQuery(userInsertQuery, userParams);
            const userId = userResult[0][0].value;

            // Insert user profile
            const profileInsertQuery = `
                INSERT INTO user_profiles (
                    user_id, firstname, lastname, age, gender, email, mobile_number
                ) VALUES (@param0, @param1, @param2, @param3, @param4, @param5, @param6)
            `;
            const profileParams = [
                { type: TYPES.Int, value: userId },
                { type: TYPES.NVarChar, value: firstname },
                { type: TYPES.NVarChar, value: lastname },
                { type: TYPES.Int, value: age ? parseInt(age, 10) : null },
                { type: TYPES.NVarChar, value: gender },
                { type: TYPES.NVarChar, value: email },
                { type: TYPES.NVarChar, value: mobilenumber }
            ];
            await executeQuery(profileInsertQuery, profileParams);

            res.status(201).json({ 
                message: "User registered successfully", 
                userId 
            });

        } catch (err) {
            console.error('Signup transaction error:', err);
            res.status(500).json({ 
                message: "Server error during registration",
                error: err.message 
            });
        }
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ 
            message: "Server error during registration",
            error: err.message 
        });
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const query = `
            SELECT user_id, username, password 
            FROM user_credentials 
            WHERE username = @param0
        `;
        const params = [
            { type: TYPES.NVarChar, value: username }
        ];

        const result = await executeQuery(query, params);

        if (result.length === 0) {
            return res.status(400).json({ message: "User not found" });
        }

        const user = {
            id: result[0][0].value,
            username: result[0][1].value,
            password: result[0][2].value
        };

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
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: "Server error" });
    }
});

// Upload endpoint
app.post('/upload', multer().single('image'), async (req, res) => {
    try {
        const file = req.file;
        const fileName = `${Date.now()}-${file.originalname}`;
        
        const blob = bucket.file(fileName);
        const blobStream = blob.createWriteStream();

        blobStream.on('finish', async () => {
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;
            res.status(200).json({ imageUrl: publicUrl });
        });

        blobStream.on('error', (err) => {
            res.status(500).json({ error: 'Upload failed', details: err.message });
        });

        blobStream.end(file.buffer);
    } catch (error) {
        res.status(500).json({ error: 'Upload failed', details: error.message });
    }
});

// Check Connection Endpoint
app.get('/check', async (req, res) => {
    try {
        const query = 'SELECT GETUTCDATE() as currentDate';
        const result = await executeQuery(query);
        
        const currentDate = result[0][0].value; // Extract date from Tedious result

        res.status(200).json({
            status: 'Connected',
            message: 'Database connection successful',
            currentDate: new Date(currentDate).toISOString()
        });
    } catch (err) {
        res.status(500).json({
            status: 'Failed',
            message: 'Database connection error',
            error: err.message
        });
    }
});

// Scan endpoint
app.post("/save", async (req, res) => {
    try {
        const { user_profile_id, disease_prediction, disease_prediction_score, scan_image } = req.body;
        
        const missingFields = [];

        if (!scan_image) missingFields.push('scan_image');
        if (!user_profile_id) missingFields.push('user_profile_id');
        if (!disease_prediction) missingFields.push('disease_prediction');
        if (!disease_prediction_score) missingFields.push('disease_prediction_score');

        if (missingFields.length > 0) {
            return res.status(400).json({ 
                message: "Missing required fields", 
                missingFields: missingFields 
            });
        }

        // Query to insert leaf scan
        const leafScanQuery = `
            INSERT INTO rice_leaf_scan (
                user_id,
                rice_leaf_disease_id,
                disease_confidence_score,
                created_at,
                scan_image
            ) 
            VALUES (@param0, @param1, @param2, GETDATE(), @param3);
            SELECT SCOPE_IDENTITY() as rice_leaf_scan_id;
        `;

        const leafScanParams = [
            { type: TYPES.VarChar, value: user_profile_id.toString() },
            { type: TYPES.Int, value: parseInt(disease_prediction, 10) },
            { type: TYPES.Float, value: parseFloat(disease_prediction_score) },
            { type: TYPES.VarChar, value: scan_image }
        ];

        try {
            // Execute leaf scan insertion
            const leafScanResult = await executeQuery(leafScanQuery, leafScanParams);
            const rice_leaf_scan_id = leafScanResult[0][0].value;

            // Insert into scan history
            const scanHistoryQuery = `
                INSERT INTO scan_history (
                    rice_leaf_scan_id,
                    date_captured
                ) VALUES (@param0, GETDATE())
            `;

            const scanHistoryParams = [
                { type: TYPES.Int, value: rice_leaf_scan_id }
            ];

            await executeQuery(scanHistoryQuery, scanHistoryParams);

            res.status(201).json({ 
                message: "Scan data saved successfully",
                rice_leaf_scan_id: rice_leaf_scan_id
            });

        } catch (error) {
            console.error('Detailed error:', error);
            res.status(500).json({ 
                message: "Server error during scan data saving",
                error: error.message
            });
        }
    } catch (err) {
        console.error('Detailed error:', err);
        res.status(500).json({ 
            message: "Server error during scan data saving",
            error: err.message
        });
    } 
});

// Disease Info Endpoint
app.get('/disease-info/:classNumber', async (req, res) => {
    try {
        const { classNumber } = req.params;
        
        const query = `
            SELECT 
              rld.rice_leaf_disease,
              rld.description as disease_description,
              rld.medicine_id,
              rld.treatment_id,
              lpt.treatment,
              lpt.description as treatment_description,
              rpm.rice_plant_medicine,
              rpm.description as medicine_description
            FROM 
              rice_leaf_disease rld
            LEFT JOIN 
              local_practice_treatment lpt ON rld.treatment_id = lpt.treatment_id
            LEFT JOIN 
              rice_plant_medicine rpm ON rld.medicine_id = rpm.medicine_id
            WHERE 
              rld.rice_leaf_disease_id = @param0
        `;
        
        const params = [
            { type: TYPES.Int, value: parseInt(classNumber, 10) }
        ];
        
        const result = await executeQuery(query, params);
        
        if (result.length === 0) {
            return res.status(404).json({ 
                error: 'No disease information found for the given class number' 
            });
        }
        
        // Convert Tedious result to a more readable object
        const diseaseInfo = {
            rice_leaf_disease: result[0][0].value,
            disease_description: result[0][1].value,
            medicine_id: result[0][2].value,
            treatment_id: result[0][3].value,
            treatment: result[0][4].value,
            treatment_description: result[0][5].value,
            rice_plant_medicine: result[0][6].value,
            medicine_description: result[0][7].value
        };
        
        res.json(diseaseInfo);
    } catch (error) {
        console.error('Error fetching disease information:', error);
        res.status(500).json({ 
            error: 'Internal server error while fetching disease information',
            details: error.message
        });
    }
});

// Home endpoint
app.get("/", (req, res) => {
    res.json({
        status: "online",
        message: "Server is running na mga neighbors",
        timestamp: new Date().toISOString()
    });
});

// Start server
async function startServer() {
    try {
        // Initialize database connection
        await initDatabaseConnection();

        // Start express server
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    } catch (err) {
        console.error("Failed to start server:", err);
        process.exit(1);
    }
}

// Shutdown handler
process.on('SIGINT', async () => {
    try {
        if (connection) {
            connection.close();
        }
        if (connector) {
            connector.close();
        }
        console.log('Database connection closed');
    } catch (err) {
        console.error('Error closing database connection:', err);
    }
    process.exit();
});

startServer();