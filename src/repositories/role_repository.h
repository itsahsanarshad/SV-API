#pragma once

#include <vector>
#include <optional>
#include <string>
#include <memory>
#include "db/database.h"
#include "models/user.h"

namespace repositories {

class RoleRepository {
public:
    explicit RoleRepository(std::shared_ptr<db::Database> database)
        : db_(database) {}

    std::vector<models::Role> find_all() {
        std::vector<models::Role> roles;

        auto result = db_->query(
            "SELECT role_id, role_name, created_at, updated_at, is_deleted "
            "FROM roles WHERE is_deleted = FALSE ORDER BY role_name ASC"
        );

        for (const auto& row : result) {
            roles.push_back(models::Role::from_row(row));
        }

        return roles;
    }

    std::optional<models::Role> find_by_id(const std::string& role_id) {
        auto result = db_->query_params(
            "SELECT role_id, role_name, created_at, updated_at, is_deleted "
            "FROM roles WHERE role_id = $1 AND is_deleted = FALSE",
            pqxx::params{role_id}
        );

        if (result.empty()) {
            return std::nullopt;
        }

        return models::Role::from_row(result[0]);
    }

private:
    std::shared_ptr<db::Database> db_;
};

} // namespace repositories
