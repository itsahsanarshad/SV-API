#pragma once

#include "crow.h"
#include <string>
#include <memory>
#include "services/auth_service.h"

namespace middleware {

struct JWTAuth {
    struct context {
        bool authenticated = false;
        std::string user_id;
        std::string email;
        std::string full_name;
        std::string error;
    };

    JWTAuth(std::shared_ptr<services::AuthService> auth_service)
        : auth_service_(auth_service) {}

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        std::string path = req.url;

        if (path.find("/auth/") != std::string::npos) {
            ctx.authenticated = true;
            return;
        }

        if (path == "/" || path == "/health") {
            ctx.authenticated = true;
            return;
        }

        std::string auth_header = req.get_header_value("Authorization");

        if (auth_header.empty()) {
            ctx.error = "No authorization header";
            res.code = 401;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"success":false,"message":"Authorization required","error":{"code":401}})";
            res.end();
            return;
        }

        const std::string bearer_prefix = "Bearer ";
        if (auth_header.substr(0, bearer_prefix.length()) != bearer_prefix) {
            ctx.error = "Invalid authorization format";
            res.code = 401;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"success":false,"message":"Invalid authorization format. Use: Bearer <token>","error":{"code":401}})";
            res.end();
            return;
        }

        std::string token = auth_header.substr(bearer_prefix.length());

        auto payload = auth_service_->validate_token(token);

        if (!payload.valid) {
            ctx.error = payload.error;
            res.code = 401;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"success":false,"message":"Invalid or expired token","error":{"code":401}})";
            res.end();
            return;
        }

        ctx.authenticated = true;
        ctx.user_id = payload.user_id;
        ctx.email = payload.email;
        ctx.full_name = payload.full_name;
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx) {
    }

private:
    std::shared_ptr<services::AuthService> auth_service_;
};

} // namespace middleware
