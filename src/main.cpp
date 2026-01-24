#include "crow.h"
#include <iostream>
#include <memory>

#include "config/config.h"
#include "db/database.h"
#include "services/auth_service.h"
#include "middleware/auth_middleware.h"
#include "middleware/cors_middleware.h"
#include "handlers/auth_handler.h"
#include "handlers/resource_handler.h"
#include "repositories/base_repository.h"
#include "routes/auth_routes.h"
#include "routes/resource_routes.h"
#include "models/response.h"

int main() {
    config::AppConfig app_config = config::load_config();

    std::cout << "Initializing database connection..." << std::endl;
    auto database = db::create_database(app_config.database);

    auto auth_service = std::make_shared<services::AuthService>(database, app_config.jwt);
    auto resource_repository = std::make_shared<repositories::ResourceRepository>(database);

    auto auth_handler = std::make_shared<handlers::AuthHandler>(auth_service);
    auto resource_handler = std::make_shared<handlers::ResourceHandler>(resource_repository);

    crow::App<middleware::CORS, middleware::JWTAuth> app(
        middleware::CORS{},
        middleware::JWTAuth{auth_service}
    );

    CROW_ROUTE(app, "/")
    ([]() {
        crow::json::wvalue response;
        response["message"] = "Crow REST API";
        response["version"] = "1.0.0";
        response["endpoints"]["auth"] = "/api/v1/auth";
        response["endpoints"]["resources"] = "/api/v1/resources";
        return response;
    });

    CROW_ROUTE(app, "/health")
    ([]() {
        crow::json::wvalue response;
        response["status"] = "healthy";
        return response;
    });

    crow::Blueprint api_v1("api/v1");

    crow::Blueprint auth_bp("auth");
    routes::register_auth_routes(auth_bp, auth_handler);

    crow::Blueprint resources_bp("resources");
    routes::register_resource_routes(resources_bp, resource_handler, app);

    api_v1.register_blueprint(auth_bp);
    api_v1.register_blueprint(resources_bp);
    app.register_blueprint(api_v1);

    CROW_CATCHALL_ROUTE(app)
    ([](crow::response& res) {
        if (res.code == 404) {
            res.set_header("Content-Type", "application/json");
            res.body = models::error_response(404, "Endpoint not found").dump();
        } else if (res.code == 405) {
            res.set_header("Content-Type", "application/json");
            res.body = models::error_response(405, "Method not allowed").dump();
        }
        res.end();
    });

    std::cout << "Starting Crow REST API on port " << app_config.server.port << std::endl;
    std::cout << "API Endpoints:" << std::endl;
    std::cout << "  POST /api/v1/auth/register - Register new user" << std::endl;
    std::cout << "  POST /api/v1/auth/login    - Login user" << std::endl;
    std::cout << "  POST /api/v1/auth/forgot-password - Request password reset" << std::endl;
    std::cout << "  POST /api/v1/auth/reset-password  - Reset password with token" << std::endl;
    std::cout << "  GET  /api/v1/auth/users    - List all users" << std::endl;
    std::cout << "  PUT  /api/v1/auth/users/:id - Update user information" << std::endl;
    std::cout << "  DELETE /api/v1/auth/users/:id - Revoke user access (soft delete)" << std::endl;
    std::cout << "  PATCH /api/v1/auth/users/:id/restore - Grant user access (restore)" << std::endl;
    std::cout << "  GET  /api/v1/resources     - List resources (auth required)" << std::endl;
    std::cout << "  GET  /api/v1/resources/:id - Get resource (auth required)" << std::endl;
    std::cout << "  POST /api/v1/resources     - Create resource (auth required)" << std::endl;
    std::cout << "  PUT  /api/v1/resources/:id - Update resource (auth required)" << std::endl;
    std::cout << "  DELETE /api/v1/resources/:id - Delete resource (auth required)" << std::endl;

    app.port(app_config.server.port)
       .concurrency(app_config.server.threads)
       .run();

    return 0;
}
