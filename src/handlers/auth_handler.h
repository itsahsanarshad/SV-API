#pragma once

#include "crow.h"
#include <memory>
#include "services/auth_service.h"
#include "models/response.h"

namespace handlers {

class AuthHandler {
public:
    explicit AuthHandler(std::shared_ptr<services::AuthService> auth_service)
        : auth_service_(auth_service) {}

    crow::response handle_register(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("email") || !body.has("password")) {
            return models::bad_request("Email and password are required");
        }

        std::string email = body["email"].s();
        std::string password = body["password"].s();
        std::string first_name = body["first_name"].s();
        std::string last_name = body["last_name"].s();
        std::string contact_number = body["contact_number"].s();

        auto result = auth_service_->register_user(first_name, last_name, contact_number, email, password);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        crow::json::wvalue data;
        data["token"] = result.token;
        data["user"] = result.user->to_json();

        return models::make_created(data, result.message);
    }

    crow::response handle_login(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("email") || !body.has("password")) {
            return models::bad_request("Email and password are required");
        }

        std::string email = body["email"].s();
        std::string password = body["password"].s();

        auto result = auth_service_->login(email, password);

        if (!result.success) {
            return models::unauthorized(result.message);
        }

        crow::json::wvalue data;
        data["token"] = result.token;
        data["user"] = result.user->to_json();

        return models::make_success(data, result.message);
    }

private:
    std::shared_ptr<services::AuthService> auth_service_;
};

} // namespace handlers
