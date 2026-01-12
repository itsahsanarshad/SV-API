#pragma once

#include "crow.h"
#include <memory>
#include "handlers/resource_handler.h"
#include "middleware/auth_middleware.h"

namespace routes {

template<typename App>
void register_resource_routes(crow::Blueprint& bp, std::shared_ptr<handlers::ResourceHandler> handler, App& app) {
    CROW_BP_ROUTE(bp, "/").methods("GET"_method)
    ([&app, handler](const crow::request& req) {
        auto& ctx = app.template get_context<middleware::JWTAuth>(req);
        return handler->handle_get_all(ctx.user_id);
    });

    CROW_BP_ROUTE(bp, "/<string>").methods("GET"_method)
    ([&app, handler](const crow::request& req, const std::string& id) {
        auto& ctx = app.template get_context<middleware::JWTAuth>(req);
        return handler->handle_get_one(id, ctx.user_id);
    });

    CROW_BP_ROUTE(bp, "/").methods("POST"_method)
    ([&app, handler](const crow::request& req) {
        auto& ctx = app.template get_context<middleware::JWTAuth>(req);
        return handler->handle_create(req, ctx.user_id);
    });

    CROW_BP_ROUTE(bp, "/<string>").methods("PUT"_method)
    ([&app, handler](const crow::request& req, const std::string& id) {
        auto& ctx = app.template get_context<middleware::JWTAuth>(req);
        return handler->handle_update(id, req, ctx.user_id);
    });

    CROW_BP_ROUTE(bp, "/<string>").methods("DELETE"_method)
    ([&app, handler](const crow::request& req, const std::string& id) {
        auto& ctx = app.template get_context<middleware::JWTAuth>(req);
        return handler->handle_delete(id, ctx.user_id);
    });
}

} // namespace routes
