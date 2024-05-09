#pragma once
// Copyright (c) 2018-2023 The Pastel Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <iomanip>
#include <sstream>
#include <cmath>

namespace ed_crypto {
    class crypto_exception : public std::exception
    {
        std::string message;
    public:
        crypto_exception(const std::string &error, const std::string &details, const std::string &func_name)
        {
            std::ostringstream str_str;
            str_str << func_name << " - " << error << ": " << details << std::endl;
            message = str_str.str();
        }

        [[nodiscard]] const char *what() const noexcept override
        {
            return message.c_str();
        }
    };
}