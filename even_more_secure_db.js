// Switch to or create the 'searchcheck' database
use searchcheck;

// ====================================
// Users Collection (With Password Security)
// ====================================
db.createCollection("users");

db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ phone_number: 1 }, { unique: true });

db.users.insertMany([
    {
        first_name: "John",
        last_name: "Doe",
        email: "johndoe@example.com",
        password_hash: "hashed_password", // Store hashed password
        salt: "random_salt_value", // Salt for password hashing
        phone_number: "123-456-7890",
        account_status: "active", // Active, suspended, etc.
        role: "user", // User roles: user, admin, etc.
        created_at: new Date(),
        updated_at: new Date()
    },
    {
        first_name: "Jane",
        last_name: "Smith",
        email: "janesmith@example.com",
        password_hash: "hashed_password", // Store hashed password
        salt: "random_salt_value",
        phone_number: "987-654-3210",
        account_status: "active",
        role: "admin", // Admin role
        created_at: new Date(),
        updated_at: new Date()
    }
]);

// ====================================
// Payments Collection
// ====================================
db.createCollection("payments");

db.payments.createIndex({ user_id: 1 });
db.payments.createIndex({ payment_date: 1 });

db.payments.insertMany([
    {
        user_id: 1,
        amount: 49.99,
        payment_method: "Credit Card",
        payment_date: new Date(),
        status: "completed"
    },
    {
        user_id: 2,
        amount: 99.99,
        payment_method: "PayPal",
        payment_date: new Date(),
        status: "pending"
    }
]);

// ====================================
// Subscriptions Collection
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
    },
    {
        plan_name: "Basic",
        description: "Access to basic breach data.",
        price: 19.99,
        duration: "monthly",
        features: ["Basic search", "Standard support"],
        created_at: new Date()
    }
]);

// ====================================
// User Subscriptions Collection
// ====================================
db.createCollection("user_subscriptions");

db.user_subscriptions.createIndex({ user_id: 1 });
db.user_subscriptions.createIndex({ plan_id: 1 });

db.user_subscriptions.insertMany([
    {
        user_id: 1,
        plan_id: 1,
        start_date: new Date(),
        end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        status: "active"
    },
    {
        user_id: 2,
        plan_id: 2,
        start_date: new Date(),
        end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        status: "active"
    }
]);

// ====================================
// Authentication Logs Collection
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
        status: "success"
    },
    {
        user_id: 2,
        login_time: new Date(),
        ip_address: "192.168.1.2",
        user_agent: "Mozilla/5.0",
        status: "failed"
    }
]);

// ====================================
// API Keys Collection
// ====================================
db.createCollection("api_keys");

db.api_keys.createIndex({ user_id: 1 });
db.api_keys.createIndex({ api_key: 1 }, { unique: true });

db.api_keys.insertMany([
    {
        user_id: 1,
        api_key: "api_key_1234567890",
        permissions: ["read", "write"],
        created_at: new Date(),
        status: "active"
    },
    {
        user_id: 2,
        api_key: "api_key_0987654321",
        permissions: ["read"],
        created_at: new Date(),
        status: "inactive"
    }
]);

// ====================================
// Backup Logs Collection
// ====================================
db.createCollection("backup_logs");

db.backup_logs.createIndex({ backup_start_time: 1 });

db.backup_logs.insertMany([
    {
        backup_name: "backup_2024_12_01",
        backup_start_time: new Date(),
        backup_end_time: new Date(),
        status: "success",
        details: "Backup completed successfully."
    }
]);

// ====================================
// System Settings Collection
// ====================================
db.createCollection("system_settings");

db.system_settings.createIndex({ setting_name: 1 });

db.system_settings.insertMany([
    {
        setting_name: "api_rate_limit",
        value: "1000",
        description: "Maximum API requests per hour",
        last_updated: new Date()
    },
    {
        setting_name: "enable_logs",
        value: "true",
        description: "Enable system logging",
        last_updated: new Date()
    }
]);

// ====================================
// User Notifications Collection
// ====================================
db.createCollection("user_notifications");

db.user_notifications.createIndex({ user_id: 1 });
db.user_notifications.createIndex({ created_at: 1 });

db.user_notifications.insertMany([
    {
        user_id: 1,
        notification_type: "Alert",
        message: "Your account has been accessed from a new location.",
        read_status: false,
        created_at: new Date()
    },
    {
        user_id: 2,
        notification_type: "Info",
        message: "Your payment has been processed.",
        read_status: true,
        created_at: new Date()
    }
]);

// ====================================
// Support Tickets Collection
// ====================================
db.createCollection("support_tickets");

db.support_tickets.createIndex({ user_id: 1 });
db.support_tickets.createIndex({ status: 1 });

db.support_tickets.insertMany([
    {
        user_id: 1,
        ticket_type: "Account Issue",
        description: "I cannot log into my account.",
        created_at: new Date(),
        status: "open"
    },
    {
        user_id: 2,
        ticket_type: "Billing Issue",
        description: "I was charged incorrectly.",
        created_at: new Date(),
        status: "resolved"
    }
]);

// ====================================
// API Error Logs Collection
// ====================================
db.createCollection("api_error_logs");

db.api_error_logs.createIndex({ endpoint: 1 });
db.api_error_logs.createIndex({ error_code: 1 });

db.api_error_logs.insertMany([
    {
        endpoint: "/api/v1/search",
        error_code: 500,
        error_message: "Internal Server Error",
        timestamp: new Date()
    }
]);

// ====================================
// Data Export Requests Collection
// ====================================
db.createCollection("data_export_requests");

db.data_export_requests.createIndex({ user_id: 1 });
db.data_export_requests.createIndex({ status: 1 });

db.data_export_requests.insertMany([
    {
        user_id: 1,
        data_type: "search_history",
        requested_at: new Date(),
        status: "pending"
    }
]);

// ====================================
// System Version History Collection
// ====================================
db.createCollection("version_history");

db.version_history.createIndex({ version: 1 });

db.version_history.insertMany([
    {
        version: "1.0.0",
        release_date: new Date(),
        changes: "Initial release."
    }
]);

// ====================================
// Security Measures: Indexing and Data Integrity
// ====================================
db.users.createIndex({ email: 1 }, { unique: true });
db.api_keys.createIndex({ api_key: 1 }, { unique: true });
db.payments.createIndex({ user_id: 1 });
db.subscriptions.createIndex({ plan_name: 1 });
db.user_subscriptions.createIndex({ user_id: 1, plan_id: 1 });
db.authentication_logs.createIndex({ login_time: 1 });
db.support_tickets.createIndex({ user_id: 1 });
db.support_tickets.createIndex({ status: 1 });

print("Collections and indexes created successfully.");
