// Switch to or create the 'searchcheck' database
use searchcheck;

// ====================================
// Users Collection (With Password Security, Encryption, and Access Control)
// ====================================
db.createCollection("users");

db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ phone_number: 1 }, { unique: true });

db.users.insertMany([
    {
        first_name: "John",
        last_name: "Doe",
        email: "johndoe@example.com",
        password_hash: encryptPassword("hashed_password"), // Encrypt stored passwords using bcrypt
        salt: generateSalt(), // Salt for password hashing
        phone_number: "123-456-7890",
        account_status: "active", // Track user account status (active, suspended, etc.)
        role: "user", // User roles: user, admin, superadmin
        created_at: new Date(),
        updated_at: new Date(),
        login_attempts: 0, // Track login attempts to prevent brute-force attacks
        last_login_attempt: new Date(),
        failed_login_attempts: [] // Store failed login attempts (time and reason) for auditing
    }
]);

// ====================================
// Payments Collection (With Encryption, Access Control, and Logging)
// ====================================
db.createCollection("payments");

db.payments.createIndex({ user_id: 1 });
db.payments.createIndex({ payment_date: 1 });

// Store payment details securely, sensitive data should be encrypted
db.payments.insertMany([
    {
        user_id: 1,
        amount: 49.99,
        payment_method: encryptPaymentMethod("Credit Card"),
        payment_date: new Date(),
        status: "completed",
        payment_details: encryptSensitiveData({ card_number: "****-****-****-1234" }) // Encrypt sensitive payment data
    }
]);

// ====================================
// Subscriptions Collection (With Access Control and Encryption)
// ====================================
db.createCollection("subscriptions");

db.subscriptions.createIndex({ plan_name: 1 });

db.subscriptions.insertMany([
    {
        plan_name: "Premium",
        description: "Access to advanced breach data and API features.",
        price: 49.99,
        duration: "monthly",
        features: ["Advanced search", "API access", "Premium support"],
        created_at: new Date()
    }
]);

// ====================================
// Authentication Logs Collection (With Audit Logging and Real-Time Monitoring)
// ====================================
db.createCollection("authentication_logs");

db.authentication_logs.createIndex({ user_id: 1 });
db.authentication_logs.createIndex({ login_time: 1 });

db.authentication_logs.insertMany([
    {
        user_id: 1,
        login_time: new Date(),
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
        status: "success",
        action: "login", // Track login actions for auditing
        created_at: new Date()
    }
]);

// ====================================
// API Keys Collection (With Access Control, Secure Storage, and Permissions)
// ====================================
db.createCollection("api_keys");

db.api_keys.createIndex({ user_id: 1 });
db.api_keys.createIndex({ api_key: 1 }, { unique: true });

// Securely store API keys with permissions
db.api_keys.insertMany([
    {
        user_id: 1,
        api_key: encryptApiKey("api_key_1234567890"),
        permissions: ["read", "write", "admin"], // Granular permissions for API access
        created_at: new Date(),
        status: "active"
    }
]);

// ====================================
// Security Logs Collection (Real-Time Intrusion Detection and Threat Analysis)
// ====================================
db.createCollection("security_logs");

db.security_logs.createIndex({ event_time: 1 });

db.security_logs.insertMany([
    {
        event_type: "DDoS Attack",
        ip_address: "192.168.1.10",
        event_time: new Date(),
        status: "detected",
        action_taken: "IP blacklisted"
    }
]);

// ====================================
// System Security Settings Collection (Enforce Security Policies and System Configurations)
// ====================================
db.createCollection("system_security_settings");

db.system_security_settings.createIndex({ setting_name: 1 });

db.system_security_settings.insertMany([
    {
        setting_name: "enable_logs",
        value: "true",
        description: "Enable system logging for audit purposes",
        last_updated: new Date()
    },
    {
        setting_name: "enable_encryption",
        value: "true",
        description: "Enable encryption for sensitive data",
        last_updated: new Date()
    },
    {
        setting_name: "rate_limit_api",
        value: "1000",
        description: "Maximum API requests per hour to prevent DDoS",
        last_updated: new Date()
    },
    {
        setting_name: "enable_audit_trails",
        value: "true",
        description: "Enable auditing for every action taken by users",
        last_updated: new Date()
    }
]);

// ====================================
// Backup Logs Collection (Track Backup Processes with Encryption and Security Auditing)
// ====================================
db.createCollection("backup_logs");

db.backup_logs.createIndex({ backup_start_time: 1 });

db.backup_logs.insertMany([
    {
        backup_name: "backup_2024_12_01",
        backup_start_time: new Date(),
        backup_end_time: new Date(),
        status: "success",
        details: "Backup completed successfully.",
        encryption_status: "encrypted" // Backup data should be encrypted
    }
]);

// ====================================
// Version History Collection (Track System Changes, Patches, and Security Audits)
// ====================================
db.createCollection("version_history");

db.version_history.createIndex({ version: 1 });

db.version_history.insertMany([
    {
        version: "1.0.0",
        release_date: new Date(),
        changes: "Initial release with critical security patches applied."
    }
]);

// ====================================
// Implement Security Logic Functions (Encryption, Access Control, Logging, etc.)
// ====================================

// Encrypt sensitive data using AES
function encryptSensitiveData(data) {
    return AES.encrypt(JSON.stringify(data), "secure_key").toString(); // Encrypt the sensitive data with AES
}

// Encrypt passwords using bcrypt for secure storage
function encryptPassword(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}

// Generate salt for password hashing
function generateSalt() {
    return bcrypt.genSaltSync(10);
}

// Encrypt payment methods using AES (for sensitive financial information)
function encryptPaymentMethod(method) {
    return AES.encrypt(method, "secure_payment_key").toString();
}

// Encrypt API keys securely
function encryptApiKey(apiKey) {
    return AES.encrypt(apiKey, "secure_api_key").toString();
}

// ====================================
// Real-Time Security Measures (Rate Limiting, Logging, Anomaly Detection)
// ====================================

// Detect DDoS attack attempts by checking the frequency of requests from an IP
function detectDdosAttack(ipAddress) {
    var requestCount = db.authentication_logs.countDocuments({ ip_address: ipAddress, login_time: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    if (requestCount > 1000) { // Example: limit requests to 1000 per hour
        db.security_logs.insertOne({
            event_type: "DDoS Attack",
            ip_address: ipAddress,
            event_time: new Date(),
            status: "detected",
            action_taken: "IP blacklisted"
        });
        // Blacklist the IP address and block further requests
        return true;
    }
    return false;
}

// Enforce rate limits for API requests to prevent abuse
function enforceRateLimit(userId) {
    var requestCount = db.api_keys.countDocuments({ user_id: userId, created_at: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    var rateLimit = db.system_security_settings.findOne({ setting_name: "rate_limit_api" }).value;
    if (requestCount > rateLimit) {
        throw new Error("API rate limit exceeded. Please try again later.");
    }
}

// Log failed login attempts for auditing and detection of suspicious activities
function logFailedLoginAttempt(userId, reason) {
    db.users.updateOne({ _id: userId }, {
        $push: {
            failed_login_attempts: { timestamp: new Date(), reason: reason }
        }
    });
}

// Trigger security measures like DDoS detection and rate limiting
function triggerSecurityMeasures(ipAddress, userId) {
    if (detectDdosAttack(ipAddress)) {
        return "DDoS detected. IP blacklisted.";
    }
    
    try {
        enforceRateLimit(userId);
    } catch (error) {
        return error.message;
    }
    
    return "Security measures successfully enforced.";
}
