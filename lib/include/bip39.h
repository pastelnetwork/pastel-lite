#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>

const uint32_t HARDENED_KEY_LIMIT = 0x80000000;

enum Language : uint32_t
{
    English = 0,
    SimplifiedChinese = 1,
    TraditionalChinese = 2,
    Czech = 3,
    French = 4,
    Italian = 5,
    Japanese = 6,
    Korean = 7,
    Portuguese = 8,
    Spanish = 9,
};

class BIP39 {
    static std::vector<std::string> get_wordlist(Language language);
public:
    static std::string entropy_to_phrase(const std::vector<unsigned char>& entropy, Language language);
    static std::vector<unsigned char> phrase_to_seed(const std::string& phrase, const std::string& passphrase = "");
    static bool validate_phrase(const std::string& phrase, Language language);
};
