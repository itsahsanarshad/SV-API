#pragma once

#include "crow.h"
#include <memory>
#include "repositories/role_repository.h"
#include "models/response.h"

namespace handlers {

class RoleHandler {
public:
    explicit RoleHandler(std::shared_ptr<repositories::RoleRepository> repository)
        : repository_(repository) {}

    crow::response handle_get_all() {
        try {
            auto roles = repository_->find_all();

            crow::json::wvalue::list role_list;
            for (const auto& role : roles) {
                role_list.push_back(role.to_json());
            }

            crow::json::wvalue data;
            data["roles"] = std::move(role_list);
            data["count"] = static_cast<int>(roles.size());

            return models::make_success(std::move(data));
        } catch (const std::exception& e) {
            return models::internal_error("Failed to fetch roles", e.what());
        }
    }

private:
    std::shared_ptr<repositories::RoleRepository> repository_;
};

} // namespace handlers
