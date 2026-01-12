#pragma once

#include <vector>
#include <optional>
#include <string>
#include <memory>
#include "db/database.h"
#include "models/user.h"

namespace repositories {

class ResourceRepository {
public:
    explicit ResourceRepository(std::shared_ptr<db::Database> database)
        : db_(database) {}

    std::vector<models::Resource> find_all(const std::string& user_id) {
        std::vector<models::Resource> resources;

        auto result = db_->query_params(
            "SELECT id, name, description, user_id, created_at, updated_at "
            "FROM resources WHERE user_id = $1 ORDER BY created_at DESC",
            pqxx::params{user_id}
        );

        for (const auto& row : result) {
            resources.push_back(models::Resource::from_row(row));
        }

        return resources;
    }

    std::optional<models::Resource> find_by_id(const std::string& id, const std::string& user_id) {
        auto result = db_->query_params(
            "SELECT id, name, description, user_id, created_at, updated_at "
            "FROM resources WHERE id = $1 AND user_id = $2",
            pqxx::params{id, user_id}
        );

        if (result.empty()) {
            return std::nullopt;
        }

        return models::Resource::from_row(result[0]);
    }

    std::optional<models::Resource> create(const std::string& name, const std::string& description, const std::string& user_id) {
        auto result = db_->query_params(
            "INSERT INTO resources (name, description, user_id) "
            "VALUES ($1, $2, $3) "
            "RETURNING id, name, description, user_id, created_at, updated_at",
            pqxx::params{name, description, user_id}
        );

        if (result.empty()) {
            return std::nullopt;
        }

        return models::Resource::from_row(result[0]);
    }

    std::optional<models::Resource> update(const std::string& id, const std::string& name, const std::string& description, const std::string& user_id) {
        auto result = db_->query_params(
            "UPDATE resources SET name = $1, description = $2, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = $3 AND user_id = $4 "
            "RETURNING id, name, description, user_id, created_at, updated_at",
            pqxx::params{name, description, id, user_id}
        );

        if (result.empty()) {
            return std::nullopt;
        }

        return models::Resource::from_row(result[0]);
    }

    bool remove(const std::string& id, const std::string& user_id) {
        auto result = db_->query_params(
            "DELETE FROM resources WHERE id = $1 AND user_id = $2 RETURNING id",
            pqxx::params{id, user_id}
        );

        return !result.empty();
    }

private:
    std::shared_ptr<db::Database> db_;
};

} // namespace repositories
