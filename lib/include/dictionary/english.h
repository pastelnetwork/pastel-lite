#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>

struct WordList_english {
    static constexpr const char* words[] = {
            "abandon", "ability", "able"
    };
    static constexpr size_t size = sizeof(words) / sizeof(words[0]);
};
