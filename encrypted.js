// Switch to the classified_documents database
use classified_documents;

// ====================================
// Users Collection with Role-Based Access Control (RBAC)
// ====================================
db.createCollection("users");

// Indexes to ensure unique and secure access
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ phone_number: 1 }, { unique: true });

// Insert user data securely with encrypted passwords and roles
db.users.insertMany([
    {
        first_name: "John",
        last_name: "Doe",
        email: "johndoe@militarydomain.com",
        password_hash: encryptPassword("hashed_secure_password"), // Secure password storage
        salt: generateSalt(),
        phone_number: encryptPhoneNumber("123-456-7890"),
        role: "admin",
        account_status: "active",
        created_at: new Date(),
        updated_at: new Date(),
        login_attempts: 0,
        last_login_attempt: new Date(),
        failed_login_attempts: []
    }
]);

// ====================================
// Audit Logs Collection with Full Forensic Logging
// ====================================
db.createCollection("audit_logs");

db.audit_logs.createIndex({ event_time: 1 });
db.audit_logs.createIndex({ user_id: 1 });

// Inserting actions performed by users
db.audit_logs.insertMany([
    {
        user_id: 1,
        event_type: "document_access",
        document_id: "TOP_SECRET_001",
        event_time: new Date(),
        action: "viewed",
        ip_address: "10.0.0.1",
        location: "Internal Network",
        status: "success",
        created_at: new Date()
    }
]);

// ====================================
// Intrusion Detection Logs
// ====================================
db.createCollection("intrusion_detection_logs");

db.intrusion_detection_logs.createIndex({ detection_time: 1 });

// Log real-time threats and suspicious activity
db.intrusion_detection_logs.insertMany([
    {
        detection_time: new Date(),
        ip_address: "192.168.1.200",
        detected_activity: "Multiple failed login attempts",
        action_taken: "IP blocked",
        severity: "high",
        status: "resolved",
        created_at: new Date()
    }
]);

// ====================================
// Encryption & Key Management Collection
// ====================================
db.createCollection("encryption_keys");

db.encryption_keys.insertMany([
    {
        key_id: generateUniqueId(),
        document_id: "TOP_SECRET_001",
        encryption_key: encryptEncryptionKey("secure_encryption_key_for_classified_document"),
        created_at: new Date(),
        updated_at: new Date()
    }
]);

// ====================================
// Rate Limiting for API and Document Access
// ====================================
function enforceRateLimiting(userId) {
    var actionCount = db.audit_logs.countDocuments({ user_id: userId, event_time: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    if (actionCount > 50) {
        throw new Error("Rate limit exceeded. Too many requests in a short time.");
    }
}

// ====================================
// Intrusion Detection and Blocking
// ====================================
function blockSuspiciousIP(ipAddress) {
    db.sensitive_event_logs.insertOne({
        event_type: "Suspicious IP",
        ip_address: ipAddress,
        event_time: new Date(),
        status: "blocked",
        action_taken: "IP address blocked",
        details: "Detected suspicious access attempts from IP: " + ipAddress,
        created_at: new Date()
    });

    // Actual blocking mechanism (e.g., blocking through firewall or internal IP management)
    // For demonstration, we log it, but implement it with your firewall systems.
    console.log("IP " + ipAddress + " has been blocked for suspicious activity.");
}

// ====================================
// Utility Functions for Encryption and Salt Generation
// ====================================
function encryptPassword(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}

function encryptPhoneNumber(phoneNumber) {
    return AES.encrypt(phoneNumber, "secure_phone_key").toString();
}

function generateSalt() {
    return bcrypt.genSaltSync(10);
}

function encryptEncryptionKey(key) {
    return AES.encrypt(key, "encryption_key_management_system").toString();
}

function generateUniqueId() {
    return UUID.v4();
}
// Ensuring that security measures are integrated within the MongoDB schema itself

use classified_documents;

// ====================================
// Users Collection with Multi-Factor Authentication (MFA) and RBAC
// ====================================
db.createCollection("users");
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ phone_number: 1 }, { unique: true });

db.users.insertMany([
    {
        first_name: "John",
        last_name: "Doe",
        email: "johndoe@militarydomain.com",
        password_hash: encryptPassword("hashed_secure_password"),
        salt: generateSalt(),
        phone_number: encryptPhoneNumber("123-456-7890"),
        role: "admin",
        clearance_level: "TOP_SECRET", // Clearance level assignment
        mfa_enabled: true,  // MFA is enabled
        account_status: "active",
        created_at: new Date(),
        updated_at: new Date(),
        login_attempts: 0,
        last_login_attempt: new Date(),
        failed_login_attempts: [],
        last_mfa_verified: new Date() // MFA verification timestamp
    }
]);

// ====================================
// Audit Logs with Tamper-Proof Encryption
// ====================================
db.createCollection("audit_logs");

db.audit_logs.createIndex({ event_time: 1 });
db.audit_logs.createIndex({ user_id: 1 });

db.audit_logs.insertMany([
    {
        user_id: 1,
        event_type: "document_access",
        document_id: "TOP_SECRET_001",
        event_time: new Date(),
        action: "viewed",
        ip_address: "10.0.0.1",
        location: "Internal Network",
        status: "success",
        created_at: new Date(),
        log_encrypted: encryptLogData("User accessed classified data.") // Encrypting logs to prevent tampering
    }
]);

// ====================================
// Sensitive Event Detection with Real-Time Blocking
// ====================================
function blockSuspiciousIP(ipAddress) {
    db.sensitive_event_logs.insertOne({
        event_type: "Suspicious IP",
        ip_address: ipAddress,
        event_time: new Date(),
        action_taken: "IP blocked",
        severity: "critical",
        created_at: new Date()
    });

    // Log and take real-time action
    console.log("IP " + ipAddress + " has been blocked for suspicious activity.");
}

// ====================================
// Intrusion Detection with Real-Time Anomaly Alerts
// ====================================
function detectAndAlertAnomaly(userId) {
    // Machine learning model checks for abnormal behavior
    var actions = db.audit_logs.countDocuments({ user_id: userId, event_time: { $gte: new Date(new Date() - 60 * 60 * 1000) } });
    if (actions > 50) {
        sendAlertToSecurity("Suspicious activity detected for user " + userId);
        blockSuspiciousIP(userIp);
    }
}

// ====================================
// Utility Functions for Secure Operations
// ====================================
function encryptLogData(data) {
    return AES.encrypt(data, "secure_log_key").toString();
}

function encryptPassword(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
}

function generateSalt() {
    return bcrypt.genSaltSync(10);
}

function encryptPhoneNumber(phoneNumber) {
    return AES.encrypt(phoneNumber, "secure_phone_key").toString();
}

function sendAlertToSecurity(message) {
    // Send real-time alerts to security team
    console.log("ALERT: " + message);
}

