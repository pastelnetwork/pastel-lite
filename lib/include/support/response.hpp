#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <exception>
#include <type_traits>
#include "json/json.hpp"

// Base template declaration
template<typename T>
std::string createResponse(const T& responseData);

// Specialization for std::string
template<>
std::string createResponse(const std::string& responseData) {
    nlohmann::json j;
    j["result"] = true;
    j["data"] = responseData;
    return j.dump();
}

// Specialization for boolean
std::string createResponse(const bool& responseData) {
    nlohmann::json j;
    j["result"] = true;
    j["data"] = responseData;
    return j.dump();
}

// Specialization for uint32_t
std::string createResponse(const uint32_t& responseData) {
    nlohmann::json j;
    j["result"] = true;
    j["data"] = responseData;
    return j.dump();
}

// Specialization for std::vector<std::string>
std::string createResponse(const std::vector<std::string>& responseData) {
    nlohmann::json j;
    j["result"] = true;
    j["data"] = responseData;
    return j.dump();
}

// Success response
std::string createSuccessResponse() {
    nlohmann::json j;
    j["result"] = true;
    j["data"] = nullptr;
    return j.dump();
}

// Error handling
std::string createErrorResponse(const std::string &errorMessage) {
    nlohmann::json j;
    j["result"] = false;
    j["error"] = errorMessage;
    return j.dump();
}

// Overload for functions that return a value
template<typename F, typename R = std::invoke_result_t<F>>
std::enable_if_t<!std::is_void_v<R>, std::string> wrapResponse(F &&func) {
    try {
        return createResponse(func());
    } catch (const std::exception &e) {
        return createErrorResponse(e.what());
    }
}

// Overload for functions that return void
template<typename F, typename R = std::invoke_result_t<F>>
std::enable_if_t<std::is_void_v<R>, std::string> wrapResponse(F &&func) {
    try {
        func();
        return createSuccessResponse();
    } catch (const std::exception &e) {
        return createErrorResponse(e.what());
    }
}
