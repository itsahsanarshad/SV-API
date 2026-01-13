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
                "INSERT INTO users (first_name, last_name, contact_number, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING user_uuid, first_name, last_name, email, password_hash, created_at",
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
                "SELECT user_uuid, first_name, last_name, email, password_hash, created_at FROM users WHERE email = $1 ",
                pqxx::params{email}
            );

            if (result.empty()) {
                return {false, "", "Invalid email or password"};
            }

            models::User user = models::User::from_row(result[0]);

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

private:
    std::shared_ptr<db::Database> db_;
    config::JWTConfig jwt_config_;

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
