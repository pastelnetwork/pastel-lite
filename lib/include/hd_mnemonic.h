#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "types.h"
#include "streams.h"
#include "hd_seed.h"
#include "version.h"
#include "bip39.h"

class MnemonicSeed: public HDSeed {
    Language language;
    SecureString mnemonic;

    bool SetSeedFromMnemonic() {
        try {
            seed = BIP39::phrase_to_seed(mnemonic, "");
            return true;
        } catch (const std::exception &e) {
            return false;
        }
    }

    MnemonicSeed() = default;

public:
    static std::optional<MnemonicSeed> FromPhrase(const Language languageIn, SecureString mnemonicIn) {
        MnemonicSeed seed;
        seed.language = languageIn;
        seed.mnemonic = std::move(mnemonicIn);
        if (seed.SetSeedFromMnemonic()) {
            return seed;
        } else {
            return std::nullopt;
        }
    }

    /**
     * Randomly generate a new mnemonic seed. A SLIP-44 coin type is required to make it possible
     * to check that the generated seed can produce valid transparent and unified addresses at account
     * numbers 0x7FFFFFFF and 0x00 respectively.
     */
    static MnemonicSeed Random(uint32_t bip44CoinType, Language language = English, size_t entropyLen = 32);

    static std::optional<MnemonicSeed>
    FromEntropy(const RawHDSeed &entropy, uint32_t bip44CoinType, Language language = English);

    [[nodiscard]] CKeyingMaterial EncryptMnemonicSeed() const {
        CSecureDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << seed;
        CKeyingMaterial vchSecret(ss.begin(), ss.end());
        return vchSecret;
    }

    static std::string LanguageName(const Language language) {
        switch (language) {
            case English:
                return "English";
            case SimplifiedChinese:
                return "Simplified Chinese";
            case TraditionalChinese:
                return "Traditional Chinese";
            case Czech:
                return "Czech";
            case French:
                return "French";
            case Italian:
                return "Italian";
            case Japanese:
                return "Japanese";
            case Korean:
                return "Korean";
            case Portuguese:
                return "Portuguese";
            case Spanish:
                return "Spanish";
            default:
                return "INVALID";
        }
    }

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if (ser_action == SERIALIZE_ACTION::Read) {
            uint32_t language0;

            READWRITE(language0);
            READWRITE(mnemonic);
            language = (Language) language0;
            if (!SetSeedFromMnemonic()) {
                throw std::ios_base::failure("Invalid mnemonic phrase or language code.");
            }
        } else {
            auto language0 = (uint32_t) language;

            READWRITE(language0);
            READWRITE(mnemonic);
        }
    }

    template<typename Stream>
    static MnemonicSeed Read(Stream &stream) {
        MnemonicSeed seed;
        stream >> seed;
        return seed;
    }

    [[nodiscard]] const Language GetLanguage() const {
        return language;
    }

    [[nodiscard]] const SecureString &GetMnemonic() const {
        return mnemonic;
    }

    friend bool operator==(const MnemonicSeed &a, const MnemonicSeed &b) {
        return a.seed == b.seed;
    }

    friend bool operator!=(const MnemonicSeed &a, const MnemonicSeed &b) {
        return !(a == b);
    }
};
