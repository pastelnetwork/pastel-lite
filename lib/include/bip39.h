#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <stdexcept>
#include <bitset>
#include <openssl/sha.h>
#include <openssl/evp.h>


class BIP39 {
    // Utility function to split a string by delimiter into a vector
    static std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(str);
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

public:
    // Converts entropy (as a hex string) to a mnemonic phrase using a predefined wordlist
    static std::string entropy_to_phrase(const std::string& entropy, const std::vector<std::string>& wordlist) {
        if (entropy.length() % 2 != 0 || wordlist.size() != 2048) {
            throw std::invalid_argument("Invalid entropy or wordlist size.");
        }

        // Convert hex string to binary string
        std::string binaryString;
        for (size_t i = 0; i < entropy.length(); i += 2) {
            std::string byteString = entropy.substr(i, 2);
            char byte = static_cast<char>(std::stoul(byteString, nullptr, 16));
            binaryString += std::bitset<8>(byte).to_string();
        }

        // Split the binary string into chunks of 11 bits, each representing a word
        std::string mnemonic;
        for (size_t i = 0; i < binaryString.length(); i += 11) {
            std::string wordBits = binaryString.substr(i, 11);
            size_t wordIndex = std::bitset<11>(wordBits).to_ulong();
            mnemonic += wordlist[wordIndex] + (i + 11 < binaryString.length() ? " " : "");
        }

        return mnemonic;
    }

    // Converts a mnemonic phrase to a seed with an optional passphrase
    static std::vector<unsigned char> phrase_to_seed(const std::string& phrase, const std::string& passphrase = "") {
        const std::string salt = "mnemonic" + passphrase;
        std::vector<unsigned char> seed(64); // 512 bits

        // Use PBKDF2 with HMAC-SHA512
        PKCS5_PBKDF2_HMAC(
                phrase.c_str(), phrase.length(),
                reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                2048, // Recommended iteration count for BIP39
                EVP_sha512(),
                seed.size(), seed.data());

        return seed;
    }

    // Validates a mnemonic phrase against the wordlist
    static bool validate_phrase(const std::string& phrase, const std::vector<std::string>& wordlist) {
        auto words = split(phrase, ' ');
        for (const auto& word : words) {
            if (std::find(wordlist.begin(), wordlist.end(), word) == wordlist.end()) {
                return false;
            }
        }
        return true;
    }
};
