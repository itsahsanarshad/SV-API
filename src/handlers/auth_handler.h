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

        if (!body.has("role_id") || std::string(body["role_id"].s()).empty()) {
            return models::bad_request("role_id is required");
        }

        std::string email = body["email"].s();
        std::string password = body["password"].s();
        std::string first_name = body["first_name"].s();
        std::string last_name = body["last_name"].s();
        std::string contact_number = body["contact_number"].s();
        std::string role_id = body["role_id"].s();

        auto result = auth_service_->register_user(first_name, last_name, contact_number, email, password, role_id);

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
        std::string locale = body.has("locale") ? std::string(body["locale"].s()) : "en";

        auto result = auth_service_->login(email, password, locale);

        if (!result.success) {
            return models::unauthorized(result.message);
        }

        // 2FA pending response
        if (result.pending_2fa) {
            crow::json::wvalue data;
            data["pending_2fa"] = true;
            data["user_id"] = result.user_id;
            return models::make_success(data, result.message);
        }

        // Direct login response (for backwards compat if 2FA disabled)
        crow::json::wvalue data;
        data["token"] = result.token;
        data["user"] = result.user->to_json();

        return models::make_success(data, result.message);
    }

    crow::response handle_verify_2fa(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("user_id") || !body.has("code")) {
            return models::bad_request("user_id and code are required");
        }

        std::string user_id = body["user_id"].s();
        std::string code = body["code"].s();

        auto result = auth_service_->verify_2fa(user_id, code);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        crow::json::wvalue data;
        data["token"] = result.token;
        data["user"] = result.user->to_json();

        return models::make_success(data, result.message);
    }

    crow::response handle_resend_2fa(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("user_id")) {
            return models::bad_request("user_id is required");
        }

        std::string user_id = body["user_id"].s();
        std::string locale = body.has("locale") ? std::string(body["locale"].s()) : "en";

        auto result = auth_service_->resend_2fa(user_id, locale);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        crow::json::wvalue data;
        data["pending_2fa"] = true;
        data["user_id"] = result.user_id;

        return models::make_success(data, result.message);
    }


    crow::response handle_forgot_password(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("email")) {
            return models::bad_request("Email is required");
        }

        std::string email = body["email"].s();
        std::string locale = body.has("locale") ? std::string(body["locale"].s()) : "en";

        // Validate locale (supported: en, es, fr)
        if (locale != "en" && locale != "es" && locale != "fr") {
            locale = "en"; // Default to English for unsupported locales
        }

        auto result = auth_service_->request_password_reset(email, locale);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        return models::make_success_msg(result.message);
    }

    crow::response handle_reset_password(const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("token") || !body.has("new_password")) {
            return models::bad_request("Token and new password are required");
        }

        std::string token = body["token"].s();
        std::string new_password = body["new_password"].s();

        auto result = auth_service_->reset_password(token, new_password);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        return models::make_success_msg(result.message);
    }

    crow::response handle_list_users() {
        try {
            auto users = auth_service_->get_all_users();

            crow::json::wvalue::list user_list;
            for (const auto& user : users) {
                user_list.push_back(user.to_json_full());
            }

            crow::json::wvalue data;
            data["users"] = std::move(user_list);
            data["count"] = static_cast<int>(users.size());

            return models::make_success(std::move(data));
        } catch (const std::exception& e) {
            return models::internal_error("Failed to fetch users", e.what());
        }
    }

    crow::response handle_revoke_access(const std::string& user_uuid) {
        auto result = auth_service_->revoke_user_access(user_uuid);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        return models::make_success_msg(result.message);
    }

    crow::response handle_grant_access(const std::string& user_uuid) {
        auto result = auth_service_->grant_user_access(user_uuid);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        return models::make_success_msg(result.message);
    }

    crow::response handle_update_user(const crow::request& req, const std::string& user_uuid) {
        try {
            auto body = crow::json::load(req.body);
            if (!body) {
                return models::bad_request("Invalid JSON");
            }

            std::string first_name = body.has("first_name") ? std::string(body["first_name"].s()) : std::string();
            std::string last_name = body.has("last_name") ? std::string(body["last_name"].s()) : std::string();
            std::string email = body.has("email") ? std::string(body["email"].s()) : std::string();
            std::string contact_number = body.has("contact_number") ? std::string(body["contact_number"].s()) : std::string();
            std::string role_id = body.has("role_id") ? std::string(body["role_id"].s()) : std::string();

            auto result = auth_service_->update_user(user_uuid, first_name, last_name, email, contact_number, role_id);

            if (!result.success) {
                return models::bad_request(result.message);
            }

            crow::json::wvalue data;
            data["user"] = result.user.to_json();
            data["message"] = result.message;

            return models::make_success(std::move(data));

        } catch (const std::exception& e) {
            return models::internal_error("Failed to update user", e.what());
        }
    }

    crow::response handle_update_password(const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) {
            return models::bad_request("Invalid JSON body");
        }

        if (!body.has("email") || !body.has("old_password") || !body.has("new_password")) {
            return models::bad_request("Email, old password, and new password are required");
        }

        std::string email = body["email"].s();
        std::string old_password = body["old_password"].s();
        std::string new_password = body["new_password"].s();

        auto result = auth_service_->update_password(email, old_password, new_password);

        if (!result.success) {
            return models::bad_request(result.message);
        }

        return models::make_success_msg(result.message);
    }

private:
    std::shared_ptr<services::AuthService> auth_service_;
};

} // namespace handlers
