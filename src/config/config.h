#pragma once

#include <string>
#include <cstdlib>

namespace config {

inline std::string get_env(const std::string& key, const std::string& default_value = "") {
    const char* val = std::getenv(key.c_str());
    return val ? std::string(val) : default_value;
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

struct AppConfig {
    DatabaseConfig database;
    JWTConfig jwt;
    ServerConfig server;
};

inline AppConfig load_config() {
    return AppConfig{};
}

} // namespace config
