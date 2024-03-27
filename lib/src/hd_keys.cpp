// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "hd_keys.h"
#include "bip39.h"

std::optional<AccountKey> AccountKey::MakeAccount(const HDSeed& seed, uint32_t bip44CoinType, AccountId accountId) {
    auto rawSeed = seed.RawSeed();
    auto m = CExtKey::Master(rawSeed.data(), rawSeed.size());
    if (!m.has_value()) return std::nullopt;

    // We use a fixed keypath scheme of m/44'/coin_type'/account'
    // Derive m/44'
    auto m_44h = m.value().Derive(44 | HARDENED_KEY_LIMIT);
    if (!m_44h.has_value()) return std::nullopt;

    // Derive m/44'/coin_type'
    auto m_44h_cth = m_44h.value().Derive(bip44CoinType | HARDENED_KEY_LIMIT);
    if (!m_44h_cth.has_value()) return std::nullopt;

    // Derive m/44'/coin_type'/account_id'
    auto accountKeyOpt = m_44h_cth.value().Derive(accountId | HARDENED_KEY_LIMIT);
    if (!accountKeyOpt.has_value()) return std::nullopt;

    auto accountKey = accountKeyOpt.value();
    auto external = accountKey.Derive(0);
    auto internal = accountKey.Derive(1);

    if (!(external.has_value() && internal.has_value())) return std::nullopt;

    return AccountKey(accountKey, external.value(), internal.value());
}

std::optional<CKey> AccountKey::DeriveExternalSpendingKey(uint32_t addrIndex) const {
    auto childKey = external.Derive(addrIndex);
    if (!childKey.has_value()) return std::nullopt;
    return childKey.value().key;
}
