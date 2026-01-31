#pragma once

#include <string>
#include <optional>
#include <random>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <jwt-cpp/jwt.h>
#include "config/config.h"
#include "db/database.h"
#include "models/user.h"
#include "services/email_service.h"

namespace services {

class AuthService {
public:
    AuthService(std::shared_ptr<db::Database> database, const config::JWTConfig& jwt_config, std::shared_ptr<EmailService> email_service = nullptr)
        : db_(database), jwt_config_(jwt_config), email_service_(email_service) {}

    struct AuthResult {
        bool success = false;
        std::string token;
        std::string message;
        std::optional<models::User> user;
        // 2FA fields
        bool pending_2fa = false;
        std::string user_id;
    };

    AuthResult register_user(
        const std::string& first_name,
        const std::string& last_name,
        const std::string& contact_number,
        const std::string& email,
        const std::string& password,
        const std::string& role_id = "") {
        if (email.empty() || password.empty()) {
            return {false, "", "Email and password are required"};
        }

        if (password.length() < 6) {
            return {false, "", "Password must be at least 6 characters"};
        }

        try {
            auto existing = db_->query_params(
                "SELECT user_uuid FROM users WHERE email = $1",
                pqxx::params{email}
            );

            if(!existing.empty()){
                return {false, "", "Email already registered"};
            }

            // Validate role_id exists before creating user
            if (!role_id.empty()) {
                auto role_check = db_->query_params(
                    "SELECT role_id FROM roles WHERE role_id = $1 AND is_deleted = FALSE",
                    pqxx::params{role_id}
                );
                if (role_check.empty()) {
                    return {false, "", "Invalid role_id. Role does not exist."};
                }
            }

            std::string salt = generate_salt();
            std::string password_hash = hash_password(password, salt);


            auto result = db_->query_params(
                "INSERT INTO users (first_name, last_name, contact_number, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING user_uuid, first_name, last_name, contact_number, email, password_hash, created_at",
                pqxx::params{first_name, last_name, contact_number, email, salt + ":" + password_hash}
            );

            if (result.empty()) {
                return {false, "", "Failed to create user"};
            }

            models::User user = models::User::from_row(result[0]);

            // Assign role to user if role_id is provided
            if (!role_id.empty()) {
                db_->execute_non_query_params(
                    "INSERT INTO users_roles_assignment (user_uuid, role_id) VALUES ($1, $2)",
                    pqxx::params{user.user_uuid, role_id}
                );
            }

            std::string full_name = user.first_name + " " + user.last_name;
            std::string token = generate_token(user.user_uuid, user.email, full_name, "", "");

            return {true, token, "User registered successfully", user};

        } catch (const std::exception& e) {
            return {false, "", std::string("Registration failed: ") + e.what()};
        }
    }

    AuthResult login(const std::string& email, const std::string& password, const std::string& locale = "en") {
        if (email.empty() || password.empty()) {
            return {false, "", "Email and password are required"};
        }

        try {
            auto result = db_->query_params(
                "SELECT user_uuid, first_name, last_name, contact_number, email, password_hash, created_at, is_deleted FROM users WHERE email = $1 ",
                pqxx::params{email}
            );

            if (result.empty()) {
                return {false, "", "Invalid email or password"};
            }

            models::User user = models::User::from_row(result[0]);

            // Check if user access is revoked
            bool is_deleted = result[0]["is_deleted"].as<bool>();
            if (is_deleted) {
                return {false, "", "Access denied. Your account has been revoked."};
            }

            if (!verify_password(password, user.password_hash)) {
                return {false, "", "Invalid email or password"};
            }

            // Generate 2FA code
            std::string code = generate_2fa_code();

            // Invalidate any existing codes for this user
            db_->execute_non_query_params(
                "UPDATE two_factor_codes SET used = TRUE WHERE user_uuid = $1 AND used = FALSE",
                pqxx::params{user.user_uuid}
            );

            // Store 2FA code with 10 minute expiry
            db_->execute_non_query_params(
                "INSERT INTO two_factor_codes (user_uuid, code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes')",
                pqxx::params{user.user_uuid, code}
            );

            // Send 2FA code via email
            if (email_service_) {
                std::string valid_locale = (locale == "en" || locale == "es" || locale == "fr") ? locale : "en";
                email_service_->send_2fa_code_email(user.email, code, valid_locale);
            }

            // Return pending 2FA response (no token yet)
            AuthResult auth_result;
            auth_result.success = true;
            auth_result.pending_2fa = true;
            auth_result.user_id = user.user_uuid;
            auth_result.message = "Verification code sent to your email";
            return auth_result;

        } catch (const std::exception& e) {
            return {false, "", std::string("Login failed: ") + e.what()};
        }
    }

    AuthResult verify_2fa(const std::string& user_id, const std::string& code) {
        if (user_id.empty() || code.empty()) {
            return {false, "", "User ID and code are required"};
        }

        try {
            // Find valid 2FA code
            auto code_result = db_->query_params(
                "SELECT id FROM two_factor_codes WHERE user_uuid = $1 AND code = $2 AND used = FALSE AND expires_at > NOW() LIMIT 1",
                pqxx::params{user_id, code}
            );

            if (code_result.empty()) {
                return {false, "", "Invalid or expired verification code"};
            }

            // Mark code as used
            std::string code_id = code_result[0]["id"].as<std::string>();
            db_->execute_non_query_params(
                "UPDATE two_factor_codes SET used = TRUE WHERE id = $1",
                pqxx::params{code_id}
            );

            // Fetch user details
            auto user_result = db_->query_params(
                "SELECT user_uuid, first_name, last_name, contact_number, email, password_hash, created_at, is_deleted FROM users WHERE user_uuid = $1",
                pqxx::params{user_id}
            );

            if (user_result.empty()) {
                return {false, "", "User not found"};
            }

            models::User user = models::User::from_row(user_result[0]);

            // Fetch user's role
            auto role_result = db_->query_params(
                "SELECT r.role_id, r.role_name FROM roles r "
                "INNER JOIN users_roles_assignment ura ON r.role_id = ura.role_id "
                "WHERE ura.user_uuid = $1 LIMIT 1",
                pqxx::params{user.user_uuid}
            );

            std::string role_id = "";
            std::string role_name = "";
            if (!role_result.empty()) {
                role_id = role_result[0]["role_id"].as<std::string>();
                role_name = role_result[0]["role_name"].as<std::string>();
                user.role_id = role_id;
                user.role_name = role_name;
            }

            // Generate JWT token
            std::string full_name = user.first_name + " " + user.last_name;
            std::string token = generate_token(user.user_uuid, user.email, full_name, role_id, role_name);

            return {true, token, "Login successful", user};

        } catch (const std::exception& e) {
            return {false, "", std::string("Verification failed: ") + e.what()};
        }
    }

    AuthResult resend_2fa(const std::string& user_id, const std::string& locale = "en") {
        if (user_id.empty()) {
            return {false, "", "User ID is required"};
        }

        try {
            // Get user email
            auto user_result = db_->query_params(
                "SELECT email FROM users WHERE user_uuid = $1 AND is_deleted = FALSE",
                pqxx::params{user_id}
            );

            if (user_result.empty()) {
                return {false, "", "User not found"};
            }

            std::string email = user_result[0]["email"].as<std::string>();

            // Generate new 2FA code
            std::string code = generate_2fa_code();

            // Invalidate any existing codes for this user
            db_->execute_non_query_params(
                "UPDATE two_factor_codes SET used = TRUE WHERE user_uuid = $1 AND used = FALSE",
                pqxx::params{user_id}
            );

            // Store new 2FA code with 10 minute expiry
            db_->execute_non_query_params(
                "INSERT INTO two_factor_codes (user_uuid, code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes')",
                pqxx::params{user_id, code}
            );

            // Send 2FA code via email
            if (email_service_) {
                std::string valid_locale = (locale == "en" || locale == "es" || locale == "fr") ? locale : "en";
                email_service_->send_2fa_code_email(email, code, valid_locale);
            }

            AuthResult auth_result;
            auth_result.success = true;
            auth_result.pending_2fa = true;
            auth_result.user_id = user_id;
            auth_result.message = "New verification code sent to your email";
            return auth_result;

        } catch (const std::exception& e) {
            return {false, "", std::string("Resend failed: ") + e.what()};
        }
    }

    struct TokenPayload {
        bool valid = false;
        std::string user_id;
        std::string email;
        std::string full_name;
        std::string role_id;
        std::string role_name;
        std::string error;
    };

    TokenPayload validate_token(const std::string& token) {
        try {
        auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{jwt_config_.secret})
                .with_issuer("crow-api");

            verifier.verify(decoded);

            // Extract claims with fallback for backward compatibility
            std::string full_name;
            std::string role_id;
            std::string role_name;
            try {
                full_name = decoded.get_payload_claim("full_name").as_string();
            } catch (...) {
                full_name = "";
            }
            try {
                role_id = decoded.get_payload_claim("role_id").as_string();
            } catch (...) {
                role_id = "";
            }
            try {
                role_name = decoded.get_payload_claim("role_name").as_string();
            } catch (...) {
                role_name = "";
            }

            return {
                true,
                decoded.get_payload_claim("user_id").as_string(),
                decoded.get_payload_claim("email").as_string(),
                full_name,
                role_id,
                role_name,
                ""
            };

        } catch (const jwt::error::token_verification_exception& e) {
            return {false, "", "", "", "", "", "Token verification failed"};
        } catch (const std::exception& e) {
            return {false, "", "", "", "", "", std::string("Token validation error: ") + e.what()};
        }
    }

    std::vector<models::User> get_all_users() {
        std::vector<models::User> users;
        
        try {
            auto result = db_->query(
                "SELECT u.user_uuid, u.first_name, u.last_name, u.contact_number, u.email, u.password_hash, u.created_at, u.is_deleted, "
                "r.role_id, r.role_name "
                "FROM users u "
                "LEFT JOIN users_roles_assignment ura ON u.user_uuid = ura.user_uuid "
                "LEFT JOIN roles r ON ura.role_id = r.role_id "
                "ORDER BY u.created_at DESC"
            );

            for (const auto& row : result) {
                models::User user = models::User::from_row(row);
                // Add role information if available
                if (!row["role_id"].is_null()) {
                    user.role_id = row["role_id"].as<std::string>();
                    user.role_name = row["role_name"].as<std::string>();
                }
                users.push_back(user);
            }
        } catch (const std::exception& e) {
            // Return empty list on error
        }

        return users;
    }

    struct AccessResult {
        bool success = false;
        std::string message;
    };

    AccessResult revoke_user_access(const std::string& user_uuid) {
        if (user_uuid.empty()) {
            return {false, "User ID is required"};
        }

        try {
            auto result = db_->query_params(
                "UPDATE users SET is_deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_uuid = $1 AND is_deleted = FALSE RETURNING user_uuid",
                pqxx::params{user_uuid}
            );

            if (result.empty()) {
                return {false, "User not found or already revoked"};
            }

            return {true, "User access revoked successfully"};

        } catch (const std::exception& e) {
            return {false, std::string("Failed to revoke access: ") + e.what()};
        }
    }

    AccessResult grant_user_access(const std::string& user_uuid) {
        if (user_uuid.empty()) {
            return {false, "User ID is required"};
        }

        try {
            auto result = db_->query_params(
                "UPDATE users SET is_deleted = FALSE, updated_at = CURRENT_TIMESTAMP WHERE user_uuid = $1 AND is_deleted = TRUE RETURNING user_uuid",
                pqxx::params{user_uuid}
            );

            if (result.empty()) {
                return {false, "User not found or already active"};
            }

            return {true, "User access granted successfully"};

        } catch (const std::exception& e) {
            return {false, std::string("Failed to grant access: ") + e.what()};
        }
    }

    struct UpdateResult {
        bool success = false;
        std::string message;
        models::User user;
    };

    UpdateResult update_user(
        const std::string& user_uuid,
        const std::string& first_name,
        const std::string& last_name,
        const std::string& email,
        const std::string& contact_number) {
        
        if (user_uuid.empty()) {
            return {false, "User ID is required", {}};
        }

        // Validate email if provided
        if (!email.empty() && !config::is_valid_email(email)) {
            return {false, "Invalid email format", {}};
        }

        try {
            // Check if email is already taken by another user
            if (!email.empty()) {
                auto existing = db_->query_params(
                    "SELECT user_uuid FROM users WHERE email = $1 AND user_uuid != $2",
                    pqxx::params{email, user_uuid}
                );

                if (!existing.empty()) {
                    return {false, "Email already in use by another user", {}};
                }
            }

            // Update user
            auto result = db_->query_params(
                "UPDATE users SET "
                "first_name = COALESCE(NULLIF($2, ''), first_name), "
                "last_name = COALESCE(NULLIF($3, ''), last_name), "
                "email = COALESCE(NULLIF($4, ''), email), "
                "contact_number = COALESCE(NULLIF($5, ''), contact_number), "
                "updated_at = CURRENT_TIMESTAMP "
                "WHERE user_uuid = $1 AND is_deleted = FALSE "
                "RETURNING user_uuid, first_name, last_name, contact_number, email, password_hash, created_at",
                pqxx::params{user_uuid, first_name, last_name, email, contact_number}
            );

            if (result.empty()) {
                return {false, "User not found or has been deleted", {}};
            }

            models::User updated_user = models::User::from_row(result[0]);
            return {true, "User updated successfully", updated_user};

        } catch (const std::exception& e) {
            return {false, std::string("Failed to update user: ") + e.what(), {}};
        }
    }

    AuthResult update_password(const std::string& email, const std::string& old_password, const std::string& new_password) {
        if (email.empty() || old_password.empty() || new_password.empty()) {
            return {false, "", "Email, old password, and new password are required"};
        }

        if (new_password.length() < 6) {
            return {false, "", "New password must be at least 6 characters"};
        }

        try {
            // Find user by email
            auto result = db_->query_params(
                "SELECT user_uuid, password_hash FROM users WHERE email = $1",
                pqxx::params{email}
            );

            if (result.empty()) {
                return {false, "", "User not found"};
            }

            std::string user_uuid = result[0]["user_uuid"].c_str();
            std::string stored_hash = result[0]["password_hash"].c_str();

            // Verify old password
            if (!verify_password(old_password, stored_hash)) {
                return {false, "", "Incorrect old password"};
            }

            // Generate new salt and hash for new password
            std::string salt = generate_salt();
            std::string new_hash = hash_password(new_password, salt);
            std::string new_stored_hash = salt + ":" + new_hash;

            // Update password in database
            auto update_result = db_->query_params(
                "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE user_uuid = $2",
                pqxx::params{new_stored_hash, user_uuid}
            );

            return {true, "", "Password updated successfully"};

        } catch (const std::exception& e) {
            return {false, "", std::string("Failed to update password: ") + e.what()};
        }
    }



    struct ResetResult {
        bool success = false;
        std::string message;
    };

    ResetResult request_password_reset(const std::string& email, const std::string& locale = "en") {
        if (email.empty()) {
            return {false, "Email is required"};
        }

        try {
            auto result = db_->query_params(
                "SELECT user_uuid FROM users WHERE email = $1",
                pqxx::params{email}
            );

            if (result.empty()) {
                // Security: Don't reveal if email exists or not
                return {true, "If the email exists, a password reset link has been sent"};
            }

            std::string user_uuid = result[0]["user_uuid"].as<std::string>();
            std::string token = generate_reset_token();
            
            // Token expires in 1 hour
            auto now = std::chrono::system_clock::now();
            auto expires = now + std::chrono::hours(1);
            auto expires_time_t = std::chrono::system_clock::to_time_t(expires);
            std::tm expires_tm;
            #ifdef _WIN32
                localtime_s(&expires_tm, &expires_time_t);
            #else
                localtime_r(&expires_time_t, &expires_tm);
            #endif
            
            std::ostringstream expires_str;
            expires_str << std::put_time(&expires_tm, "%Y-%m-%d %H:%M:%S");

            db_->execute_non_query_params(
                "INSERT INTO password_reset_tokens (user_uuid, token, expires_at) VALUES ($1, $2, $3)",
                pqxx::params{user_uuid, token, expires_str.str()}
            );

            // Send email with reset link
            if (email_service_) {
                auto email_result = email_service_->send_password_reset_email(email, token, locale);
                if (!email_result.success) {
                    return {false, "Failed to send password reset email: " + email_result.message};
                }
            } else {
                return {false, "Email service not configured"};
            }

            return {true, "Password reset email sent successfully"};

        } catch (const std::exception& e) {
            return {false, std::string("Failed to process password reset request: ") + e.what()};
        }
    }

    struct TokenValidationResult {
        bool valid = false;
        std::string user_uuid;
        std::string error;
    };

    TokenValidationResult validate_reset_token(const std::string& token) {
        if (token.empty()) {
            return {false, "", "Token is required"};
        }

        try {
            auto result = db_->query_params(
                "SELECT user_uuid, expires_at, used FROM password_reset_tokens WHERE token = $1",
                pqxx::params{token}
            );

            if (result.empty()) {
                return {false, "", "Invalid or expired reset token"};
            }

            bool used = result[0]["used"].as<bool>();
            if (used) {
                return {false, "", "Token has already been used"};
            }

            std::string expires_at_str = result[0]["expires_at"].as<std::string>();
            std::tm expires_tm = {};
            std::istringstream ss(expires_at_str);
            ss >> std::get_time(&expires_tm, "%Y-%m-%d %H:%M:%S");
            
            auto expires_time_t = std::mktime(&expires_tm);
            auto now_time_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

            if (now_time_t > expires_time_t) {
                return {false, "", "Token has expired"};
            }

            std::string user_uuid = result[0]["user_uuid"].as<std::string>();
            return {true, user_uuid, ""};

        } catch (const std::exception& e) {
            return {false, "", std::string("Token validation error: ") + e.what()};
        }
    }

    ResetResult reset_password(const std::string& token, const std::string& new_password) {
        if (token.empty() || new_password.empty()) {
            return {false, "Token and new password are required"};
        }

        if (new_password.length() < 6) {
            return {false, "Password must be at least 6 characters"};
        }

        auto validation = validate_reset_token(token);
        if (!validation.valid) {
            return {false, validation.error};
        }

        try {
            std::string salt = generate_salt();
            std::string password_hash = hash_password(new_password, salt);

            db_->execute_non_query_params(
                "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE user_uuid = $2",
                pqxx::params{salt + ":" + password_hash, validation.user_uuid}
            );

            db_->execute_non_query_params(
                "UPDATE password_reset_tokens SET used = TRUE WHERE token = $1",
                pqxx::params{token}
            );

            return {true, "Password reset successfully"};

        } catch (const std::exception& e) {
            return {false, std::string("Password reset failed: ") + e.what()};
        }
    }

private:
    std::shared_ptr<db::Database> db_;
    config::JWTConfig jwt_config_;
    std::shared_ptr<EmailService> email_service_;

    std::string generate_reset_token(size_t length = 32) {
        std::vector<unsigned char> token_bytes(length);
        RAND_bytes(token_bytes.data(), length);

        std::stringstream ss;
        for (unsigned char byte : token_bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string generate_2fa_code() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000, 999999);
        return std::to_string(dis(gen));
    }


    std::string generate_salt(size_t length = 16) {
        std::vector<unsigned char> salt(length);
        RAND_bytes(salt.data(), length);

        std::stringstream ss;
        for (unsigned char byte : salt) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string hash_password(const std::string& password, const std::string& salt) {
        std::string salted = salt + password;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(salted.c_str()), salted.length(), hash);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    bool verify_password(const std::string& password, const std::string& stored_hash) {
        size_t delimiter_pos = stored_hash.find(':');
        if (delimiter_pos == std::string::npos) {
            return false;
        }

        std::string salt = stored_hash.substr(0, delimiter_pos);
        std::string hash = stored_hash.substr(delimiter_pos + 1);

        return hash_password(password, salt) == hash;
    }

    std::string generate_token(const std::string& user_id, const std::string& email, const std::string& full_name, const std::string& role_id, const std::string& role_name) {
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::seconds(jwt_config_.expiration_seconds);

        auto token_builder = jwt::create()
            .set_issuer("crow-api")
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("user_id", picojson::value(user_id))
            .set_payload_claim("email", picojson::value(email))
            .set_payload_claim("full_name", picojson::value(full_name));

        if (!role_id.empty()) {
            token_builder.set_payload_claim("role_id", picojson::value(role_id));
            token_builder.set_payload_claim("role_name", picojson::value(role_name));
        }

        return token_builder.sign(jwt::algorithm::hs256{jwt_config_.secret});
    }
};

} // namespace services
