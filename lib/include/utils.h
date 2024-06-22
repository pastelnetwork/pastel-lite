#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include <string>
#include <algorithm>
#include <ranges>
#include <cmath>

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

inline bool IsHex(const std::string& str) {
    return (!str.empty()) &&
           (str.size() % 2 == 0) &&
           std::ranges::all_of(str, [](char c) { return HexDigit(c) >= 0; });
}

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin)
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

template<typename T>
inline std::string HexStr(const T& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

inline std::string HexInt(uint32_t val)
{
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(sizeof(uint32_t) * 2) << std::hex << val;
    return ss.str();
}