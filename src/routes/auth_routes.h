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
}

} // namespace routes
