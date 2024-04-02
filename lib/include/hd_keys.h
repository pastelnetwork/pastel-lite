#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"
#include "key.h"
#include "hd_seed.h"

typedef std::string HDKeyPath;
typedef uint32_t AccountId;


class AccountKey {
private:
    CExtKey accountKey;
    CExtKey external;

    AccountKey(CExtKey accountKeyIn, CExtKey externalIn):
        accountKey(std::move(accountKeyIn)), external(std::move(externalIn)) {}

public:
    static std::optional<AccountKey> MakeAccount(const HDSeed& seed, uint32_t bip44CoinType, AccountId accountId);

    static HDKeyPath KeyPath(uint32_t bip44CoinType, AccountId accountId) {
        return
                "m/44'/" +
                std::to_string(bip44CoinType) + "'/" +
                std::to_string(accountId) + "'";
    }

    static HDKeyPath KeyPath(uint32_t bip44CoinType, AccountId accountId, bool external, uint32_t childIndex) {
        return
                AccountKey::KeyPath(bip44CoinType, accountId) + "/" +
                (external ? "0/" : "1/") +
                std::to_string(childIndex);
    }

    /**
     * Generate the key corresponding to the specified index at the "external child"
     * level of the path for the account.
     */
    [[nodiscard]] std::optional<CKey> Derive(uint32_t addrIndex) const;

    friend bool operator==(const AccountKey& a, const AccountKey& b)
    {
        return a.accountKey == b.accountKey;
    }

    void Clear() {
        accountKey.key.Clear();
        external.key.Clear();
    }
};
