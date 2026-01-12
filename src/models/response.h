#pragma once

#include "crow.h"
#include <string>

namespace models {

inline crow::json::wvalue success_response(crow::json::wvalue data, const std::string& message = "Success") {
    crow::json::wvalue response;
    response["success"] = true;
    response["data"] = std::move(data);
    response["message"] = message;
    response["error"] = nullptr;
    return response;
}

inline crow::json::wvalue success_response_no_data(const std::string& message = "Success") {
    crow::json::wvalue response;
    response["success"] = true;
    response["data"] = nullptr;
    response["message"] = message;
    response["error"] = nullptr;
    return response;
}

inline crow::json::wvalue error_response(int code, const std::string& message, const std::string& details = "") {
    crow::json::wvalue response;
    response["success"] = false;
    response["data"] = nullptr;
    response["message"] = message;

    crow::json::wvalue error;
    error["code"] = code;
    error["details"] = details;
    response["error"] = std::move(error);

    return response;
}

inline crow::response make_success(crow::json::wvalue data, const std::string& message = "Success") {
    crow::response res(200);
    res.set_header("Content-Type", "application/json");
    res.body = success_response(std::move(data), message).dump();
    return res;
}

inline crow::response make_success_msg(const std::string& message) {
    crow::response res(200);
    res.set_header("Content-Type", "application/json");
    res.body = success_response_no_data(message).dump();
    return res;
}

inline crow::response make_created(crow::json::wvalue data, const std::string& message = "Created successfully") {
    crow::response res(201);
    res.set_header("Content-Type", "application/json");
    res.body = success_response(std::move(data), message).dump();
    return res;
}

inline crow::response make_error(int status_code, const std::string& message, const std::string& details = "") {
    crow::response res(status_code);
    res.set_header("Content-Type", "application/json");
    res.body = error_response(status_code, message, details).dump();
    return res;
}

inline crow::response bad_request(const std::string& message = "Bad request", const std::string& details = "") {
    return make_error(400, message, details);
}

inline crow::response unauthorized(const std::string& message = "Unauthorized", const std::string& details = "") {
    return make_error(401, message, details);
}

inline crow::response forbidden(const std::string& message = "Forbidden", const std::string& details = "") {
    return make_error(403, message, details);
}

inline crow::response not_found(const std::string& message = "Not found", const std::string& details = "") {
    return make_error(404, message, details);
}

inline crow::response internal_error(const std::string& message = "Internal server error", const std::string& details = "") {
    return make_error(500, message, details);
}

} // namespace models
