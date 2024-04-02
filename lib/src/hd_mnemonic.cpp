// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>

#include "hd_mnemonic.h"
#include "hd_keys.h"

std::optional<MnemonicSeed> MnemonicSeed::FromPhrase(const Language languageIn, SecureString mnemonicIn) {
    MnemonicSeed seed;
    seed.language = languageIn;
    seed.mnemonic = std::move(mnemonicIn);
    if (seed.SetSeedFromMnemonic()) {
        return seed;
    } else {
        return std::nullopt;
    }
}

std::optional<MnemonicSeed> MnemonicSeed::FromEntropy(const RawHDSeed& entropy, uint32_t bip44CoinType, Language language) {
    auto phrase = BIP39::entropy_to_phrase(entropy, language);
    SecureString mnemonic(phrase);
    auto seed = MnemonicSeed::FromPhrase(language, mnemonic).value();

     // Verify that the seed data is valid entropy for keys at
     // account 0 and at both the public & private chain levels for account 0x7FFFFFFF.
    auto key1 = AccountKey::MakeAccount(seed, bip44CoinType, 0);
    auto key2 = AccountKey::MakeAccount(seed, bip44CoinType, HARDENED_KEY_LIMIT-1);
    if (key1.has_value() && key2.has_value()) {
        return seed;
    }
    return std::nullopt;
}

MnemonicSeed MnemonicSeed::Random(uint32_t bip44CoinType, Language language, size_t entropyLen)
{
    assert(entropyLen >= 32);
    while (true) { // loop until we find usable entropy
        RawHDSeed entropy(entropyLen, 0);
        randombytes_buf(entropy.data(), entropyLen);

        auto seed = MnemonicSeed::FromEntropy(entropy, bip44CoinType, language);
        if (seed.has_value()) {
            return seed.value();
        }
    }
}
