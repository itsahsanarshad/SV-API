#pragma once

#include "crow.h"
#include <pqxx/pqxx>
#include <string>
#include <optional>

namespace models {

struct User {
    std::string user_uuid;
    std::string first_name;
    std::string last_name;
    std::string contact_number;
    std::string email;
    std::string password_hash;
    std::string created_at;
    bool is_deleted = false;
    // Role information (populated on login)
    std::string role_id;
    std::string role_name;

    crow::json::wvalue to_json() const {
        crow::json::wvalue json;
        json["id"] = user_uuid;
        json["first_name"] = first_name;
        json["last_name"] = last_name;
        json["full_name"] = first_name + " " + last_name;
        json["email"] = email;
        json["created_at"] = created_at;
        if (!role_id.empty()) {
            json["role_id"] = role_id;
            json["role_name"] = role_name;
        }
        return json;
    }

    // Full user details for listing (excludes password_hash)
    crow::json::wvalue to_json_full() const {
        crow::json::wvalue json;
        json["id"] = user_uuid;
        json["first_name"] = first_name;
        json["last_name"] = last_name;
        json["contact_number"] = contact_number;
        json["email"] = email;
        json["created_at"] = created_at;
        json["status"] = is_deleted ? "deleted" : "active";
        return json;
    }

    static User from_row(const pqxx::row& row) {
        User user;
        user.user_uuid = row["user_uuid"].as<std::string>();
        user.first_name = row["first_name"].as<std::string>();
        user.last_name = row["last_name"].as<std::string>();
        user.contact_number = row["contact_number"].as<std::string>("");
        user.email = row["email"].as<std::string>();
        user.password_hash = row["password_hash"].as<std::string>();
        user.created_at = row["created_at"].as<std::string>();
        // Check if is_deleted column exists in result
        try {
            user.is_deleted = row["is_deleted"].as<bool>(false);
        } catch (...) {
            user.is_deleted = false;
        }
        return user;
    }
};

struct Resource {
    std::string id;
    std::string name;
    std::string description;
    std::string user_id;
    std::string created_at;
    std::string updated_at;

    crow::json::wvalue to_json() const {
        crow::json::wvalue json;
        json["id"] = id;
        json["name"] = name;
        json["description"] = description;
        json["user_id"] = user_id;
        json["created_at"] = created_at;
        json["updated_at"] = updated_at;
        return json;
    }

    static Resource from_row(const pqxx::row& row) {
        Resource resource;
        resource.id = row["id"].as<std::string>();
        resource.name = row["name"].as<std::string>();
        resource.description = row["description"].as<std::string>("");
        resource.user_id = row["user_id"].as<std::string>();
        resource.created_at = row["created_at"].as<std::string>();
        resource.updated_at = row["updated_at"].as<std::string>();
        return resource;
    }

    static std::optional<Resource> from_json(const crow::json::rvalue& json) {
        Resource resource;

        if (!json.has("name")) {
            return std::nullopt;
        }

        resource.name = json["name"].s();

        if (json.has("description")) {
            resource.description = json["description"].s();
        }

        return resource;
    }
};

struct Role {
    std::string role_id;
    std::string role_name;
    std::string created_at;
    std::string updated_at;
    bool is_deleted = false;

    crow::json::wvalue to_json() const {
        crow::json::wvalue json;
        json["role_id"] = role_id;
        json["role_name"] = role_name;
        return json;
    }

    static Role from_row(const pqxx::row& row) {
        Role role;
        role.role_id = row["role_id"].as<std::string>();
        role.role_name = row["role_name"].as<std::string>();
        try {
            role.created_at = row["created_at"].as<std::string>("");
            role.updated_at = row["updated_at"].as<std::string>("");
            role.is_deleted = row["is_deleted"].as<bool>(false);
        } catch (...) {
            // Optional fields
        }
        return role;
    }
};

} // namespace models
