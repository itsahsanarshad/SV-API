#pragma once

#include <string>
#include <cstdlib>
#include <regex>

namespace config {

inline std::string get_env(const std::string& key, const std::string& default_value = "") {
    const char* val = std::getenv(key.c_str());
    return val ? std::string(val) : default_value;
}

inline bool is_valid_email(const std::string& email) {
    if (email.empty() || email.length() > 255) return false;
    std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return std::regex_match(email, email_regex);
}

struct DatabaseConfig {
    std::string host = get_env("DB_HOST", "localhost");
    std::string port = get_env("DB_PORT", "5432");
    std::string name = get_env("DB_NAME", "serenity_vault");
    std::string user = get_env("DB_USER", "postgres");
    std::string password = get_env("DB_PASSWORD", "postgres");

    std::string connection_string() const {
        return "host=" + host +
               " port=" + port +
               " dbname=" + name +
               " user=" + user +
               " password=" + password;
    }
};

struct JWTConfig {
    std::string secret = get_env("JWT_SECRET", "serenity_vault_secret_key_assigned");
    int expiration_seconds = std::stoi(get_env("JWT_EXPIRATION", "3600"));
};

struct ServerConfig {
    int port = std::stoi(get_env("SERVER_PORT", "18080"));
    int threads = std::stoi(get_env("SERVER_THREADS", "4"));
};

struct EmailConfig {
    std::string smtp_host = get_env("SMTP_HOST", "smtp.protonmail.ch");
    std::string smtp_port = get_env("SMTP_PORT", "587");
    std::string smtp_user = get_env("SMTP_USER", "info@serenityvault.com");
    std::string smtp_password = get_env("SMTP_PASSWORD", "");
    std::string from_email = get_env("SMTP_FROM_EMAIL", "info@serenityvault.com");
    std::string from_name = get_env("SMTP_FROM_NAME", "Serenity Vault");
    std::string frontend_url = get_env("FRONTEND_URL", "http://localhost:3000");
    bool use_tls = get_env("SMTP_USE_TLS", "true") == "true";
};

struct AppConfig {
    DatabaseConfig database;
    JWTConfig jwt;
    ServerConfig server;
    EmailConfig email;
};

inline AppConfig load_config() {
    return AppConfig{};
}

} // namespace config
