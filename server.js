const express = require("express");
const bodyParser = require("body-parser");
const { Connection, Request } = require('tedious');
const { Connector } = require('@google-cloud/cloud-sql-connector');
const bcrypt = require("bcryptjs");
const { Storage } = require('@google-cloud/storage');   // add this to main repo
const multer = require('multer');                       // npm install @google-cloud/storage multer

let connector;
let connection;

/*Note to future me: 
    - wont run locally need google auth
    - will run on google run when deployed
    - tedious bug on server and port
    - dont forget to save and push!
*/

/* TO DO: 
    - implement middleware 
    - Implement specific, controlled endpoints
    Note: Mas better if during compenent connection phase na buhaton kanang duha.
*/

// MUST FIX THE SIGNUP VALIDATION CODE

async function initializeDatabase() {
    connector = new Connector();
    const clientOpts = await connector.getTediousOptions({
        instanceConnectionName: process.env.DB_SERVER, 
        ipType: 'PUBLIC',
    });

    connection = new Connection({
        server: '0.0.0.0', 
        authentication: {
            type: 'default',
            options: {
                userName: process.env.DB_USER,
                password: process.env.DB_PASSWORD,
            },
        },
        options: {
            ...clientOpts,
            port: 9999, 
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

// Helper function to execute SQL queries
const executeQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve({ rowCount, rows });
            }
        });

        params.forEach(param => {
            request.addParameter(param.name, param.type, param.value);
        });
        connection.execSql(request);
    });
};

const app = express();
app.use(bodyParser.json());

// Storage setup
const storage = new Storage({
    projectId: process.env.GOOGLE_CLOUD_PROJECT,
});
const bucket = storage.bucket(process.env.BUCKET_NAME);

// Upload endpoint
app.post('/upload', multer().single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const file = req.file;
        const fileName = `${Date.now()}-${file.originalname}`;
        const blob = bucket.file(fileName);
        const blobStream = blob.createWriteStream({
            resumable: false,
            metadata: {
                contentType: file.mimetype,
            },
        });

        blobStream.on('error', (error) => {
            res.status(500).json({ error: 'Upload failed', details: error.message });
        });

        blobStream.on('finish', async () => {
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;
            res.status(200).json({ imageUrl: publicUrl });
        });

        blobStream.end(file.buffer);
    } catch (error) {
        res.status(500).json({ error: 'Upload failed', details: error.message });
    }
});

// Home endpoint
app.get("/", (req, res) => {
    res.json({
        status: "online",
        message: "Server is running"
    });
});

// Check Connection Endpoint
app.get('/check', async (req, res) => {
    try {
        const result = await executeQuery('SELECT GETUTCDATE() as currentDate');
        res.status(200).json({
            status: 'Connected',
            message: 'Database connection successful',
            currentDate: result.rows[0][0].value
        });
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
    try {
        const { username, email, password, firstname, lastname, age, gender, mobilenumber } = req.body;

        // Validate required fields
        const requiredFields = { username, email, password, firstname, lastname };
        const missingFields = Object.entries(requiredFields)
            .filter(([_, value]) => !value)
            .map(([key]) => key);

        if (missingFields.length > 0) {
            return res.status(400).json({
                message: "Missing required fields",
                missingFields
            });
        }

        // Check if username exists in user_credentials
        const usernameCheck = await executeQuery(
            'SELECT COUNT(*) as count FROM user_credentials WHERE username = @username',
            [{ name: 'username', type: sql.NVarChar, value: username }]
        );

        if (usernameCheck.rows[0][0].value > 0) {
            return res.status(400).json({ message: "Username already exists" });
        }

        // Check if email exists in user_profiles
        const emailCheck = await executeQuery(
            'SELECT COUNT(*) as count FROM user_profiles WHERE email = @email',
            [{ name: 'email', type: sql.NVarChar, value: email }]
        );

        if (emailCheck.rows[0][0].value > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insert user
        const DEFAULT_ROLE_ID = 1; // ilisan for admin and user identifier
        const userResult = await executeQuery(
            `INSERT INTO user_credentials (username, role_id, password)
             VALUES (@username, @roleId, @hashedPassword);
             SELECT SCOPE_IDENTITY() AS userId;`,
            [
                { name: 'username', type: sql.NVarChar, value: username },
                { name: 'roleId', type: sql.Int, value: DEFAULT_ROLE_ID },
                { name: 'hashedPassword', type: sql.NVarChar, value: hashedPassword }
            ]
        );

        const userId = userResult.rows[0][0].value;

        // Insert profile
        await executeQuery(
            `INSERT INTO user_profiles (user_id, firstname, lastname, age, gender, email, mobile_number)
             VALUES (@userId, @firstname, @lastname, @age, @gender, @email, @mobilenumber)`,
            [
                { name: 'userId', type: sql.Int, value: userId },
                { name: 'firstname', type: sql.NVarChar, value: firstname },
                { name: 'lastname', type: sql.NVarChar, value: lastname },
                { name: 'age', type: sql.Int, value: age ? parseInt(age, 10) : null },
                { name: 'gender', type: sql.NVarChar, value: gender },
                { name: 'email', type: sql.NVarChar, value: email },
                { name: 'mobilenumber', type: sql.NVarChar, value: mobilenumber }
            ]
        );

        res.status(201).json({ message: "User registered successfully", userId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error during registration" });
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        const result = await executeQuery(
            'SELECT user_id, username, password FROM user_credentials WHERE username = @username',
            [{ name: 'username', type: sql.NVarChar, value: username }]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ message: "User not found" });
        }

        const user = {
            user_id: result.rows[0][0].value,
            username: result.rows[0][1].value,
            password: result.rows[0][2].value
        };

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
                missingFields
            });
        }

        const scanResult = await executeQuery(
            `INSERT INTO rice_leaf_scan (user_id, rice_leaf_disease_id, disease_confidence_score, created_at, scan_image)
             VALUES (@user_profile_id, @disease_prediction, @disease_prediction_score, GETDATE(), @scan_image);
             SELECT SCOPE_IDENTITY() as rice_leaf_scan_id;`,
            [
                { name: 'user_profile_id', type: sql.Int, value: user_profile_id },
                { name: 'disease_prediction', type: sql.Int, value: disease_prediction },
                { name: 'disease_prediction_score', type: sql.Float, value: disease_prediction_score },
                { name: 'scan_image', type: sql.NVarChar, value: scan_image }
            ]
        );

        const rice_leaf_scan_id = scanResult.rows[0][0].value;

        await executeQuery(
            `INSERT INTO scan_history (rice_leaf_scan_id, date_captured)
             VALUES (@rice_leaf_scan_id, GETDATE())`,
            [{ name: 'rice_leaf_scan_id', type: sql.Int, value: rice_leaf_scan_id }]
        );

        res.status(201).json({
            message: "Scan data saved successfully",
            rice_leaf_scan_id
        });
    } catch (err) {
        console.error('Detailed error:', err);
        res.status(500).json({
            message: "Server error during scan data saving",
            error: err.message
        });
    }
});

// Disease info endpoint
app.get('/disease-info/:classNumber', async (req, res) => {
    try {
        const { classNumber } = req.params;

        const result = await executeQuery(
            `SELECT 
                rld.rice_leaf_disease,
                rld.description as disease_description,
                rld.medicine_id,
                rld.treatment_id,
                lpt.treatment,
                lpt.description as treatment_description,
                rpm.rice_plant_medicine,
                rpm.description as medicine_description
             FROM rice_leaf_disease rld
             LEFT JOIN local_practice_treatment lpt ON rld.treatment_id = lpt.treatment_id
             LEFT JOIN rice_plant_medicine rpm ON rld.medicine_id = rpm.medicine_id
             WHERE rld.rice_leaf_disease_id = @classNumber`,
            [{ name: 'classNumber', type: sql.Int, value: parseInt(classNumber) }]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'No disease information found for the given class number'
            });
        }

        const diseaseInfo = {};
        result.rows[0].forEach((col, index) => {
            diseaseInfo[col.metadata.colName] = col.value;
        });

        res.json(diseaseInfo);
    } catch (error) {
        console.error('Error fetching disease information:', error);
        res.status(500).json({
            error: 'Internal server error while fetching disease information'
        });
    }
});

// Startup function
async function startServer() {
    try {
        await initializeDatabase();
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    } catch (err) {
        console.error("Failed to connect to database server:", err);
        process.exit(1);
    }
}

// Shutdown handler
process.on('SIGINT', async () => {
    try {
        if (connection) {
            await connection.close();
        }
        if (connector) {
            await connector.close();
        }
    } catch (err) {
        console.error("Error during shutdown:", err);
    }
    process.exit();
});

startServer();