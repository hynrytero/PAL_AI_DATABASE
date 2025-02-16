const express = require('express');
const bodyParser = require('body-parser');
const { Connection, Request, TYPES } = require('tedious');
const { Connector } = require('@google-cloud/cloud-sql-connector');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { Storage } = require('@google-cloud/storage');
const multer = require('multer');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

/*DATABASE*/
const connectionPool = [];
const MAX_POOL_SIZE = 10;

// Database Connection
async function createNewConnection() {
    try {
        const connector = new Connector();
        const clientOpts = await connector.getTediousOptions({
            instanceConnectionName: process.env.DB_SERVER,
            ipType: 'PUBLIC',
        });

        const connection = new Connection({
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
                trustServerCertificate: true,
                encrypt: false,
                connectTimeout: 30000, // 30 seconds timeout
                requestTimeout: 30000,
                retry: {
                    maxRetries: 3,
                    minTimeout: 300,
                    maxTimeout: 3000
                }
            },
        });

        return new Promise((resolve, reject) => {
            connection.connect(err => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(connection);
            });
        });
    } catch (error) {
        throw error;
    }
}

// Get an available connection from the pool
async function getConnection() {
    // Remove closed connections from the pool
    for (let i = connectionPool.length - 1; i >= 0; i--) {
        if (connectionPool[i].state.name === 'Final') {
            connectionPool.splice(i, 1);
        }
    }

    // Find an available connection
    const availableConnection = connectionPool.find(conn => 
        conn.state.name === 'LoggedIn' && !conn.isExecuting);

    if (availableConnection) {
        return availableConnection;
    }

    // Create new connection if pool isn't full
    if (connectionPool.length < MAX_POOL_SIZE) {
        const newConnection = await createNewConnection();
        connectionPool.push(newConnection);
        return newConnection;
    }

    // Wait for an available connection
    return new Promise((resolve) => {
        const checkInterval = setInterval(async () => {
            const conn = connectionPool.find(c => 
                c.state.name === 'LoggedIn' && !c.isExecuting);
            if (conn) {
                clearInterval(checkInterval);
                resolve(conn);
            }
        }, 100);
    });
}

// Modified executeQuery function
async function executeQuery(query, params = []) {
    let connection;
    try {
        connection = await getConnection();
        
        return new Promise((resolve, reject) => {
            const request = new Request(query, (err) => {
                if (err) {
                    reject(err);
                }
            });

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
    } catch (error) {
        // If connection error occurs, try to create a new connection
        if (connection && connection.state.name === 'Final') {
            const index = connectionPool.indexOf(connection);
            if (index > -1) {
                connectionPool.splice(index, 1);
            }
        }
        throw error;
    }
}



// Initialize Google Cloud Storage
const storage = new Storage({
    projectId: process.env.GOOGLE_CLOUD_PROJECT,
});
const bucket = storage.bucket(process.env.BUCKET_NAME);

// Rate Limiter
const requestLimiter = rateLimit({ // try to apply this middleware
    windowMs: 10 * 60 * 1000, 
    max: 30,
    message: 'Too many request attempts, please try again later'
});

// Email configuration
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Verification Codes Storage 
const verificationCodes = new Map();
const passwordResetCodes = new Map();

// Generate a 6-digit verification code
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}


// Create Express app
const app = express();
app.use(bodyParser.json());


/*ENDPOINTS*/

// get scan history
app.get('/api/scan-history/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const query = `
            SELECT 
                rls.rice_leaf_scan_id,
                rls.scan_image,
                rls.disease_confidence_score,
                rls.created_at,
                rld.rice_leaf_disease,
                rld.description as disease_description,
                rpm.description as medicine_description
            FROM rice_leaf_scan rls
            JOIN rice_leaf_disease rld ON rls.rice_leaf_disease_id = rld.rice_leaf_disease_id
            LEFT JOIN rice_plant_medicine rpm ON rld.medicine_id = rpm.medicine_id
            WHERE rls.user_id = @param0
            ORDER BY rls.created_at DESC
        `;

        const params = [
            { type: TYPES.Int, value: parseInt(userId) }
        ];

        const results = await executeQuery(query, params);
        
        const formattedResults = results.map(row => ({
            id: row[0].value,
            image: row[1].value,
            confidence: Math.round(row[2].value * 100),
            date: row[3].value,
            disease: row[4].value,
            diseaseDescription: row[5].value || 'No disease description available',
            medicineDescription: row[6].value || 'No medicine information available'
        }));

        res.json(formattedResults);
    } catch (error) {
        console.error('Error fetching scan history:', error);
        res.status(500).json({ error: 'Failed to fetch scan history' });
    }
});

/*SIGNUP PROCESS*/
// Initial Signup Endpoint (Pre-registration)
app.post("/pre-signup", requestLimiter, async (req, res) => {
    try {
        const { username, email, password, firstname, lastname, age, gender, mobilenumber } = req.body;

        // Check if email already exists
        const emailQuery = `
            SELECT 1 FROM user_profiles 
            WHERE email = @param0
        `;
        const emailParams = [{ type: TYPES.NVarChar, value: email }];
        const existingEmail = await executeQuery(emailQuery, emailParams);
        if (existingEmail.length > 0) {
            return res.status(409).json({
                message: "Email already in use"
            });
        }

        // Generate verification code
        const verificationCode = generateVerificationCode();
        const codeExpiry = new Date();
        codeExpiry.setMinutes(codeExpiry.getMinutes() + 15); // Code valid for 15 minutes

        // Store temporary registration details and verification code
        const tempRegData = {
            username,
            email,
            password,
            firstname,
            lastname,
            age,
            gender,
            mobilenumber,
            verificationCode,
            codeExpiry
        };
        verificationCodes.set(email, tempRegData);

        // Send verification code via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Verification Code',
            html: `
                <h1>Email Verification</h1>
                <p>Your verification code is:</p>
                <h2>${verificationCode}</h2>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not request this verification, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ 
            message: "Verification code sent to your email",
            email: email
        });

    } catch (err) {
        console.error('Pre-signup error:', err);
        res.status(500).json({ 
            message: "Server error during pre-registration",
            error: err.message 
        });
    }
});

// Complete Signup with Verification Code
app.post("/complete-signup", async (req, res) => {
    try {
        const { email, verificationCode } = req.body;

        // Retrieve stored registration data
        const tempRegData = verificationCodes.get(email);

        // Validate verification code
        if (!tempRegData || 
            tempRegData.verificationCode !== verificationCode || 
            new Date() > tempRegData.codeExpiry
        ) {
            return res.status(400).json({ 
                message: "Invalid or expired verification code" 
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(tempRegData.password, salt);

        const DEFAULT_ROLE_ID = 1;

        // Start a transaction to insert user credentials and profile
        const registrationQuery = `
            BEGIN TRANSACTION;
            
            -- Insert user credentials
            INSERT INTO user_credentials (username, role_id, password)
            VALUES (@param0, @param1, @param2);
            
            -- Get the new user ID
            DECLARE @newUserId INT = SCOPE_IDENTITY();
            
            -- Insert user profile
            INSERT INTO user_profiles (
                user_id, firstname, lastname, age, gender, email, mobile_number
            ) VALUES (
                @newUserId, @param3, @param4, @param5, @param6, @param7, @param8
            );
            
            COMMIT TRANSACTION;
            
            SELECT @newUserId AS userId;
        `;

        const registrationParams = [
            { type: TYPES.NVarChar, value: tempRegData.username },
            { type: TYPES.Int, value: DEFAULT_ROLE_ID },
            { type: TYPES.NVarChar, value: hashedPassword },
            { type: TYPES.NVarChar, value: tempRegData.firstname },
            { type: TYPES.NVarChar, value: tempRegData.lastname },
            { type: TYPES.Int, value: tempRegData.age ? parseInt(tempRegData.age, 10) : null },
            { type: TYPES.NVarChar, value: tempRegData.gender },
            { type: TYPES.NVarChar, value: email },
            { type: TYPES.NVarChar, value: tempRegData.mobilenumber }
        ];

        const userResult = await executeQuery(registrationQuery, registrationParams);
        const userId = userResult[0][0].value;

        // Remove verification code from storage
        verificationCodes.delete(email);

        res.status(201).json({ 
            message: "Registration completed successfully", 
            userId 
        });

    } catch (err) {
        console.error('Complete signup error:', err);
        res.status(500).json({ 
            message: "Server error during registration",
            error: err.message 
        });
    }
});

// Resend Verification Code Endpoint
app.post("/resend-verification-code", async (req, res) => {
    try {
        const { email } = req.body;

        // Check if there's an existing pre-registration for this email
        const tempRegData = verificationCodes.get(email);

        if (!tempRegData) {
            return res.status(400).json({ 
                message: "No pending registration found. Please start the signup process again." 
            });
        }

        // Generate new verification code
        const verificationCode = generateVerificationCode();
        const codeExpiry = new Date();
        codeExpiry.setMinutes(codeExpiry.getMinutes() + 15);

        // Update stored data with new code
        tempRegData.verificationCode = verificationCode;
        tempRegData.codeExpiry = codeExpiry;
        verificationCodes.set(email, tempRegData);

        // Send new verification code via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your New Verification Code',
            html: `
                <h1>Email Verification</h1>
                <p>Your new verification code is:</p>
                <h2>${verificationCode}</h2>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not request this verification, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.json({ 
            message: "New verification code sent to your email",
            email: email 
        });

    } catch (err) {
        console.error('Resend verification code error:', err);
        res.status(500).json({ 
            message: "Server error", 
            error: err.message 
        });
    }
});


/*FORGOT PASSWORD PROCESS*/
app.post("/forgot-password", requestLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email exists in database
        const emailQuery = `
            SELECT user_id 
            FROM user_profiles 
            WHERE email = @param0
        `;
        const emailParams = [{ type: TYPES.NVarChar, value: email }];
        const existingUser = await executeQuery(emailQuery, emailParams);

        if (existingUser.length === 0) {
            return res.status(404).json({
                message: "No account found with this email address"
            });
        }

        // Generate OTP
        const resetCode = generateVerificationCode(); 
        const codeExpiry = new Date();
        codeExpiry.setMinutes(codeExpiry.getMinutes() + 15); 

        // Store password reset details
        passwordResetCodes.set(email, {
            resetCode,
            codeExpiry,
            userId: existingUser[0][0].value 
        });

        // Send reset code via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Code',
            html: `
                <h1>Password Reset Request</h1>
                <p>Your password reset code is:</p>
                <h2>${resetCode}</h2>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not request this password reset, please ignore this email and ensure your account is secure.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ 
            message: "Password reset code sent to your email",
            email: email
        });

    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ 
            message: "Server error during password reset request",
            error: err.message 
        });
    }
});

app.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;

        // Validate input
        if (!email || !otp) {
            return res.status(400).json({
                message: "Email and OTP are required"
            });
        }

        // Check if there's a valid reset code
        const resetData = passwordResetCodes.get(email);
        if (!resetData) {
            return res.status(400).json({
                message: "No password reset request found. Please request a new OTP."
            });
        }

        // Validate OTP and expiry
        if (resetData.resetCode !== otp) {
            return res.status(400).json({
                message: "Invalid OTP"
            });
        }

        if (new Date() > resetData.codeExpiry) {
            passwordResetCodes.delete(email);
            return res.status(400).json({
                message: "OTP has expired. Please request a new one."
            });
        }

        res.status(200).json({
            message: "OTP verified successfully",
            userId: resetData.userId
        });

    } catch (err) {
        console.error('OTP verification error:', err);
        res.status(500).json({
            message: "Server error during OTP verification",
            error: err.message
        });
    }
});

// Resend Password Reset OTP Endpoint
app.post("/resend-password-otp", requestLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email exists in database
        const emailQuery = `
            SELECT user_id 
            FROM user_profiles 
            WHERE email = @param0
        `;
        const emailParams = [{ type: TYPES.NVarChar, value: email }];
        const existingUser = await executeQuery(emailQuery, emailParams);

        if (existingUser.length === 0) {
            return res.status(404).json({
                message: "No account found with this email address"
            });
        }

        // Generate new OTP
        const resetCode = generateVerificationCode();
        const codeExpiry = new Date();
        codeExpiry.setMinutes(codeExpiry.getMinutes() + 15);

        // Update stored data with new code
        passwordResetCodes.set(email, {
            resetCode,
            codeExpiry,
            userId: existingUser[0][0].value
        });

        // Send new OTP via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'New Password Reset Code',
            html: `
                <h1>Password Reset Request</h1>
                <p>Your new password reset code is:</p>
                <h2>${resetCode}</h2>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not request this password reset, please ignore this email and ensure your account is secure.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({
            message: "New password reset code sent to your email",
            email: email
        });

    } catch (err) {
        console.error('Resend password OTP error:', err);
        res.status(500).json({
            message: "Server error during OTP resend",
            error: err.message
        });
    }
});

// Change Password
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ error: 'Email and new password are required' });
    }

    try {
        // First get the user_id from user_profiles
        const getUserQuery = `
            SELECT user_id 
            FROM user_profiles 
            WHERE email = @param0`;

        const userResults = await executeQuery(getUserQuery, [
            { type: TYPES.VarChar, value: email }
        ]);

        if (!userResults || userResults.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userId = userResults[0].user_id.value;

        // Hash the new password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the password in user_credentials
        const updatePasswordQuery = `
            UPDATE user_credentials 
            SET password = @param0,
                updated_at = GETDATE()
            WHERE user_id = @param1`;

        await executeQuery(updatePasswordQuery, [
            { type: TYPES.VarChar, value: hashedPassword },
            { type: TYPES.Int, value: userId }
        ]);

        res.json({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Internal server error' });
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
        if (disease_prediction_score === null || disease_prediction_score === undefined) 
        {
            missingFields.push('disease_prediction_score');
        }
        if (disease_prediction === null || disease_prediction === undefined) 
        {
            missingFields.push('disease_prediction');
        }

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
app.get("/", requestLimiter, (req, res) => {
    res.json({
        status: "online",
        message: "Server is running na mga neighbors",
        timestamp: new Date().toISOString()
    });
});


/*SERVER CONFIG*/

// Start server
async function startServer() {
    try {
        // Start express server
        const PORT = process.env.PORT || 5000;
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
        // Close all connections in the pool
        for (const connection of connectionPool) {
            if (connection && connection.state.name !== 'Final') {
                connection.close();
            }
        }
        console.log('All database connections closed');
    } catch (err) {
        console.error('Error closing database connections:', err);
    }
    process.exit();
});

startServer();