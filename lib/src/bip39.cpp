// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "dictionary/english.h"

#include "bip39.h"

// Converts entropy (as a hex string) to a mnemonic phrase using a predefined wordlist
std::string BIP39::entropy_to_phrase(const std::vector<unsigned char>& entropy, Language language)
{
    if (entropy.size() != 16 && entropy.size() != 20 && entropy.size() != 24 && entropy.size() != 28 && entropy.size() != 32) {
        throw std::invalid_argument("Invalid entropy length");
    }

    const std::vector<std::string>& wordlist = BIP39::get_wordlist(language);
    if (wordlist.size() != 2048) {
        throw std::invalid_argument("Invalid wordlist size.");
    }

    size_t entropy_bits = entropy.size() * 8;
    size_t checksum_bits = entropy_bits / 32;
    size_t total_bits = entropy_bits + checksum_bits;

    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256(entropy.data(), entropy.size(), checksum);
    size_t checksum_int = checksum[0] >> (8 - checksum_bits);

    size_t entropy_int = 0;
    for (unsigned char i : entropy) {
        entropy_int <<= 8;
        entropy_int |= i;
    }
    entropy_int <<= checksum_bits;
    entropy_int |= checksum_int;

    std::vector<std::string> phrase;
    for (size_t i = 0; i < total_bits / 11; ++i) {
        size_t index = (entropy_int >> (total_bits - (i + 1) * 11)) & 0x7FF;
        phrase.emplace_back(wordlist[index]);
    }

    std::stringstream ss;
    for (size_t i = 0; i < phrase.size(); ++i) {
        if (i > 0) ss << " ";
        ss << phrase[i];
    }
    return ss.str();
}

// Converts a mnemonic phrase to a seed with an optional passphrase
std::vector<unsigned char> BIP39::phrase_to_seed(const std::string& phrase, const std::string& passphrase)
{
    const std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64); // 512 bits

    // Use PBKDF2 with HMAC-SHA512
    if (PKCS5_PBKDF2_HMAC(
            phrase.c_str(), phrase.length(),
            reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
            2048, // Recommended iteration count for BIP39
            EVP_sha512(),
            seed.size(), seed.data()) != 1) {
        throw std::runtime_error("Failed to derive seed from mnemonic phrase");
    }

    return seed;
}

// Validates a mnemonic phrase against the wordlist
bool BIP39::validate_phrase(const std::string& phrase, Language language) {
    std::istringstream iss(phrase);
    std::vector<std::string> phrase_words;
    std::string word;
    while (iss >> word) {
        phrase_words.push_back(word);
    }

    if (phrase_words.size() != 12 && phrase_words.size() != 15 && phrase_words.size() != 18 &&
        phrase_words.size() != 21 && phrase_words.size() != 24) {
        return false;
    }

    const std::vector<std::string> &wordlist = BIP39::get_wordlist(language);

    try {
        size_t entropy_bits = (phrase_words.size() * 11) - (phrase_words.size() / 3);
        size_t entropy_bytes = (entropy_bits + 7) / 8;
        size_t entropy = 0;

        for (size_t i = 0; i < phrase_words.size(); ++i) {
            auto it = std::find(wordlist.begin(), wordlist.end(), phrase_words[i]);
            if (it == wordlist.end()) {
                return false;
            }
            size_t index = std::distance(wordlist.begin(), it);
            entropy |= index << (11 * (phrase_words.size() - i - 1));
        }

        size_t checksum_bits = entropy_bits / 32;
        size_t checksum = entropy >> (entropy_bits - checksum_bits);
        entropy >>= checksum_bits;

        std::vector<unsigned char> entropy_bytes_vec(entropy_bytes);
        for (size_t i = 0; i < entropy_bytes; ++i) {
            entropy_bytes_vec[entropy_bytes - i - 1] = entropy & 0xFF;
            entropy >>= 8;
        }

        unsigned char checksum_expected[SHA256_DIGEST_LENGTH];
        SHA256(entropy_bytes_vec.data(), entropy_bytes_vec.size(), checksum_expected);
        size_t checksum_expected_int = checksum_expected[0] >> (8 - checksum_bits);

        return checksum == checksum_expected_int;
    } catch (...) {
        return false;
    }
}

std::vector<std::string> BIP39::get_wordlist(Language language) {
    std::vector<std::string> wordlist;
    switch (language) {
        case Language::English:
            wordlist.assign(WordList_english::words, WordList_english::words + WordList_english::size);
            break;
//        case Language::SimplifiedChinese:
//            wordlist.assign(WordList_simplified_chinese::words,
//                            WordList_simplified_chinese::words + WordList_simplified_chinese::size);
//            break;
//        case Language::TraditionalChinese:
//            wordlist.assign(WordList_traditional_chinese::words,
//                            WordList_traditional_chinese::words + WordList_traditional_chinese::size);
//            break;
//        case Language::Czech:
//            wordlist.assign(WordList_czech::words, WordList_czech::words + WordList_czech::size);
//            break;
//        case Language::French:
//            wordlist.assign(WordList_french::words, WordList_french::words + WordList_french::size);
//            break;
//        case Language::Italian:
//            wordlist.assign(WordList_italian::words, WordList_italian::words + WordList_italian::size);
//            break;
//        case Language::Japanese:
//            wordlist.assign(WordList_japanese::words, WordList_japanese::words + WordList_japanese::size);
//            break;
//        case Language::Korean:
//            wordlist.assign(WordList_korean::words, WordList_korean::words + WordList_korean::size);
//            break;
//        case Language::Portuguese:
//            wordlist.assign(WordList_portuguese::words, WordList_portuguese::words + WordList_portuguese::size);
//            break;
//        case Language::Spanish:
//            wordlist.assign(WordList_spanish::words, WordList_spanish::words + WordList_spanish::size);
//            break;
        default:
            throw std::invalid_argument("Invalid language");
    }
    return wordlist;
}
