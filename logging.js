// Switch to or create the 'searchcheck' database
use searchcheck;

// ====================================
// Users Collection (With Password Security and Encryption)
// ====================================
db.createCollection("users");

db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ phone_number: 1 }, { unique: true });

db.users.insertMany([
    {
        first_name: "John",
        last_name: "Doe",
        email: "johndoe@example.com",
        password_hash: encryptPassword("hashed_password"), // Encrypt stored passwords
        salt: generateSalt(), // Salt for password hashing
        phone_number: "123-456-7890",
        account_status: "active", // Active, suspended, etc.
        role: "user", // User roles: user, admin, etc.
        created_at: new Date(),
        updated_at: new Date(),
        login_attempts: 0, // Track login attempts to prevent brute-force attacks
        last_login_attempt: new Date()
    }
]);

// ====================================
// Payments Collection (With Encryption and Access Control)
// ====================================
db.createCollection("payments");

db.payments.createIndex({ user_id: 1 });
db.payments.createIndex({ payment_date: 1 });

// Store payment details securely, sensitive data like credit card should be encrypted
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
// Authentication Logs Collection (With Audit Logging and Access Control)
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
// API Keys Collection (With Access Control and Secure Storage)
// ====================================
db.createCollection("api_keys");

db.api_keys.createIndex({ user_id: 1 });
db.api_keys.createIndex({ api_key: 1 }, { unique: true });

// API key generation should ensure it is randomly generated and encrypted
db.api_keys.insertMany([
    {
        user_id: 1,
        api_key: encryptApiKey("api_key_1234567890"),
        permissions: ["read", "write"],
        created_at: new Date(),
        status: "active"
    }
]);

// ====================================
// Security Logs Collection (For Real-Time Monitoring and Intrusion Detection)
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
// System Security Settings Collection (For Enforcing Access Control, Encryption, and Logs)
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
    }
]);

// ====================================
// Backup Logs Collection (Track Backups with Security Measures)
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
// System Version History Collection (Track Changes and Patches for Security Auditing)
// ====================================
db.createCollection("version_history");

db.version_history.createIndex({ version: 1 });

db.version_history.insertMany([
    {
        version: "1.0.0",
        release_date: new Date(),
        changes: "Initial release. Security patches applied."
    }
]);

// ====================================
// Implement Security Logic Functions
// ====================================

// Function to encrypt sensitive data
function encryptSensitiveData(data) {
    // Use a secure encryption algorithm like AES or RSA
    return AES.encrypt(data, "secure_key").toString(); // Just an example, replace with actual encryption logic
}

// Function to encrypt password
function encryptPassword(password) {
    // Hash password using bcrypt or a similar secure hashing algorithm
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}

// Function to generate salt for password encryption
function generateSalt() {
    return bcrypt.genSaltSync(10);
}

// Function to encrypt payment method
function encryptPaymentMethod(method) {
    // Encrypt payment method data securely
    return AES.encrypt(method, "secure_payment_key").toString();
}

// Function to encrypt API key
function encryptApiKey(apiKey) {
    // Secure encryption for API keys
    return AES.encrypt(apiKey, "secure_api_key").toString();
}

// ====================================
// Real-Time Security Measures (Rate Limiting, Logging, etc.)
// ====================================

// Real-time DDoS attack detection logic (e.g., rate limiting, anomaly detection)
function detectDdosAttack(ipAddress) {
    // Check for too many requests from a single IP address in a short period
    var requestCount = db.authentication_logs.countDocuments({ ip_address: ipAddress, login_time: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    if (requestCount > 1000) {
        db.security_logs.insertOne({
            event_type: "DDoS Attack",
            ip_address: ipAddress,
            event_time: new Date(),
            status: "detected",
            action_taken: "IP blacklisted"
        });
        // Add logic to blacklist IP here
        return true;
    }
    return false;
}

// Rate limit API requests per hour
function enforceRateLimit(userId) {
    var requestCount = db.api_keys.countDocuments({ user_id: userId, created_at: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    if (requestCount > db.system_security_settings.findOne({ setting_name: "rate_limit_api" }).value) {
        throw new Error("API rate limit exceeded. Try again later.");
    }
}
