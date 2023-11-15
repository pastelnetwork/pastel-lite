#pragma once
// Copyright (c) 2018-2023 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <string>
#include <algorithm>
#include <ranges>

constexpr signed char HexDigit(char c) {
    return [c]() -> signed char {
        switch (c) {
            case '0' ... '9': return static_cast<signed char>(c - '0');
            case 'a' ... 'f': return static_cast<signed char>(10 + c - 'a');
            case 'A' ... 'F': return static_cast<signed char>(10 + c - 'A');
            default: return static_cast<signed char>(-1);
        }
    }();
}

bool IsHex(const std::string& str) {
    return (!str.empty()) &&
           (str.size() % 2 == 0) &&
           std::ranges::all_of(str, [](char c) { return HexDigit(c) >= 0; });
}
