#pragma once

#include "crow.h"
#include <memory>
#include "handlers/auth_handler.h"

namespace routes {

inline void register_auth_routes(crow::Blueprint& bp, std::shared_ptr<handlers::AuthHandler> handler) {
    CROW_BP_ROUTE(bp, "/register").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_register(req);
    });

    CROW_BP_ROUTE(bp, "/login").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_login(req);
    });

    CROW_BP_ROUTE(bp, "/verify-2fa").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_verify_2fa(req);
    });

    CROW_BP_ROUTE(bp, "/resend-2fa").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_resend_2fa(req);
    });

    CROW_BP_ROUTE(bp, "/forgot-password").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_forgot_password(req);
    });

    CROW_BP_ROUTE(bp, "/reset-password").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_reset_password(req);
    });

    CROW_BP_ROUTE(bp, "/users").methods("GET"_method)
    ([handler]() {
        return handler->handle_list_users();
    });

    CROW_BP_ROUTE(bp, "/users/<string>").methods("DELETE"_method)
    ([handler](const std::string& user_uuid) {
        return handler->handle_revoke_access(user_uuid);
    });

    CROW_BP_ROUTE(bp, "/users/<string>/restore").methods("PATCH"_method)
    ([handler](const std::string& user_uuid) {
        return handler->handle_grant_access(user_uuid);
    });

    CROW_BP_ROUTE(bp, "/users/<string>").methods("PUT"_method)
    ([handler](const crow::request& req, const std::string& user_uuid) {
        return handler->handle_update_user(req, user_uuid);
    });

    CROW_BP_ROUTE(bp, "/update-password").methods("POST"_method)
    ([handler](const crow::request& req) {
        return handler->handle_update_password(req);
    });
}

} // namespace routes
