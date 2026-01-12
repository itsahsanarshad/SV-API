#pragma once

#include "crow.h"
#include <memory>
#include "repositories/base_repository.h"
#include "models/response.h"

namespace handlers {

class ResourceHandler {
public:
    explicit ResourceHandler(std::shared_ptr<repositories::ResourceRepository> repository)
        : repository_(repository) {}

    crow::response handle_get_all(const std::string& user_id) {
        try {
            auto resources = repository_->find_all(user_id);

            crow::json::wvalue::list resource_list;
            for (const auto& resource : resources) {
                resource_list.push_back(resource.to_json());
            }

            crow::json::wvalue data;
            data["resources"] = std::move(resource_list);
            data["count"] = static_cast<int>(resources.size());

            return models::make_success(std::move(data));
        } catch (const std::exception& e) {
            return models::internal_error("Failed to fetch resources", e.what());
        }
    }

    crow::response handle_get_one(const std::string& id, const std::string& user_id) {
        try {
            auto resource = repository_->find_by_id(id, user_id);

            if (!resource) {
                return models::not_found("Resource not found");
            }

            return models::make_success(resource->to_json());
        } catch (const std::exception& e) {
            return models::internal_error("Failed to fetch resource", e.what());
        }
    }

    crow::response handle_create(const crow::request& req, const std::string& user_id) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("name")) {
            return models::bad_request("Name is required");
        }

        std::string name = body["name"].s();
        std::string description;
        if (body.has("description")) {
            description = body["description"].s();
        }

        try {
            auto resource = repository_->create(name, description, user_id);

            if (!resource) {
                return models::internal_error("Failed to create resource");
            }

            return models::make_created(resource->to_json(), "Resource created successfully");
        } catch (const std::exception& e) {
            return models::internal_error("Failed to create resource", e.what());
        }
    }

    crow::response handle_update(const std::string& id, const crow::request& req, const std::string& user_id) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        auto existing = repository_->find_by_id(id, user_id);
        if (!existing) {
            return models::not_found("Resource not found");
        }

        std::string name = existing->name;
        std::string description = existing->description;

        if (body.has("name")) {
            name = body["name"].s();
        }
        if (body.has("description")) {
            description = body["description"].s();
        }

        try {
            auto resource = repository_->update(id, name, description, user_id);

            if (!resource) {
                return models::internal_error("Failed to update resource");
            }

            return models::make_success(resource->to_json(), "Resource updated successfully");
        } catch (const std::exception& e) {
            return models::internal_error("Failed to update resource", e.what());
        }
    }

    crow::response handle_delete(const std::string& id, const std::string& user_id) {
        try {
            auto existing = repository_->find_by_id(id, user_id);
            if (!existing) {
                return models::not_found("Resource not found");
            }

            bool deleted = repository_->remove(id, user_id);

            if (!deleted) {
                return models::internal_error("Failed to delete resource");
            }

            return models::make_success_msg("Resource deleted successfully");
        } catch (const std::exception& e) {
            return models::internal_error("Failed to delete resource", e.what());
        }
    }

private:
    std::shared_ptr<repositories::ResourceRepository> repository_;
};

} // namespace handlers
