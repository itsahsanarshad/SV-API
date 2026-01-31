#pragma once

#include "crow.h"
#include <memory>
#include "handlers/role_handler.h"

namespace routes {

inline void register_role_routes(crow::Blueprint& bp, std::shared_ptr<handlers::RoleHandler> handler) {
    CROW_BP_ROUTE(bp, "/").methods("GET"_method)
    ([handler]() {
        return handler->handle_get_all();
    });
}

} // namespace routes
