#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include "json.hpp"

// Decoding for std::string
std::string decodeStringResponse(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (j["result"].get<bool>()) {
        return j["data"].get<std::string>();
    } else {
        throw std::runtime_error(j["error"].get<std::string>());
    }
}

// Decoding for bool
bool decodeBoolResponse(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (j["result"].get<bool>()) {
        return j["data"].get<bool>();
    } else {
        throw std::runtime_error(j["error"].get<std::string>());
    }
}

// Decoding for uint32_t
uint32_t decodeUint32Response(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (j["result"].get<bool>()) {
        return j["data"].get<uint32_t>();
    } else {
        throw std::runtime_error(j["error"].get<std::string>());
    }
}

// Decoding for std::vector<std::string>
std::vector<std::string> decodeVectorStringResponse(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (j["result"].get<bool>()) {
        return j["data"].get<std::vector<std::string>>();
    } else {
        throw std::runtime_error(j["error"].get<std::string>());
    }
}

// Decoding for success response
void decodeSuccessResponse(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (!j["result"].get<bool>()) {
        throw std::runtime_error(j["error"].get<std::string>());
    }
}

// Decoding for error response
std::string decodeErrorResponse(const std::string& jsonResponse) {
    nlohmann::json j = nlohmann::json::parse(jsonResponse);
    if (!j["result"].get<bool>()) {
        return j["error"].get<std::string>();
    } else {
        throw std::runtime_error("Expected an error response, but got success.");
    }
}