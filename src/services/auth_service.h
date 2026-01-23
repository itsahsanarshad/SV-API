#pragma once

#include <string>
#include <optional>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <jwt-cpp/jwt.h>
#include "config/config.h"
#include "db/database.h"
#include "models/user.h"

namespace services {

class AuthService {
public:
    AuthService(std::shared_ptr<db::Database> database, const config::JWTConfig& jwt_config)
        : db_(database), jwt_config_(jwt_config) {}

    struct AuthResult {
        bool success = false;
        std::string token;
        std::string message;
        std::optional<models::User> user;
    };

    AuthResult register_user(
        const std::string& first_name,
        const std::string& last_name,
        const std::string& contact_number,
        const std::string& email,
        const std::string& password) {
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
            std::string token = generate_token(user.user_uuid, user.email);

            return {true, token, "User registered successfully", user};

        } catch (const std::exception& e) {
            return {false, "", std::string("Registration failed: ") + e.what()};
        }
    }

    AuthResult login(const std::string& email, const std::string& password) {
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

            std::string token = generate_token(user.user_uuid, user.email);

            return {true, token, "Login successful", user};

        } catch (const std::exception& e) {
            return {false, "", std::string("Login failed: ") + e.what()};
        }
    }

    struct TokenPayload {
        bool valid = false;
        std::string user_id;
        std::string email;
        std::string error;
    };

    TokenPayload validate_token(const std::string& token) {
        try {
        auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{jwt_config_.secret})
                .with_issuer("crow-api");

            verifier.verify(decoded);

            return {
                true,
                decoded.get_payload_claim("user_id").as_string(),
                decoded.get_payload_claim("email").as_string(),
                ""
            };

        } catch (const jwt::error::token_verification_exception& e) {
            return {false, "", "", "Token verification failed"};
        } catch (const std::exception& e) {
            return {false, "", "", std::string("Token validation error: ") + e.what()};
        }
    }

    std::vector<models::User> get_all_users() {
        std::vector<models::User> users;
        
        try {
            auto result = db_->query(
                "SELECT user_uuid, first_name, last_name, contact_number, email, password_hash, created_at "
                "FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC"
            );

            for (const auto& row : result) {
                users.push_back(models::User::from_row(row));
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

    struct ResetResult {
        bool success = false;
        std::string message;
        std::string token;  // Token returned for direct use (no email)
    };

    ResetResult request_password_reset(const std::string& email) {
        if (email.empty()) {
            return {false, "Email is required", ""};
        }

        try {
            auto result = db_->query_params(
                "SELECT user_uuid FROM users WHERE email = $1",
                pqxx::params{email}
            );

            if (result.empty()) {
                return {false, "Email not found", ""};
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

            // Return token directly in response
            return {true, "Password reset token generated successfully", token};

        } catch (const std::exception& e) {
            return {false, std::string("Failed to generate reset token: ") + e.what(), ""};
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

    std::string generate_reset_token(size_t length = 32) {
        std::vector<unsigned char> token_bytes(length);
        RAND_bytes(token_bytes.data(), length);

        std::stringstream ss;
        for (unsigned char byte : token_bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
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

    std::string generate_token(const std::string& user_id, const std::string& email) {
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::seconds(jwt_config_.expiration_seconds);

        return jwt::create()
            .set_issuer("crow-api")
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("user_id", picojson::value(user_id))
            .set_payload_claim("email", picojson::value(email))
            .sign(jwt::algorithm::hs256{jwt_config_.secret});
    }
};

} // namespace services
