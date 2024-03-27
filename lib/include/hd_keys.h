#pragma once
// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"
#include "key.h"
#include "hd_seed.h"

typedef std::string HDKeyPath;
typedef uint32_t AccountId;


//   AccountKey GetLegacyAccountKey() const {
//        const auto seedOpt = GetMnemonicSeed();
//        if (!seedOpt.has_value()) {
//            throw std::runtime_error(
//                    "HDWallet::GenerateNewKey(): Wallet does not have a mnemonic seed.");
//        }
//
//        // All mnemonic seeds are checked at construction to ensure that we can obtain
//        // a valid spending key for the account ZCASH_LEGACY_ACCOUNT;
//        // therefore, the `value()` call here is safe.
//        return AccountKey::ForAccount(seedOpt.value(), BIP44CoinType(), ZCASH_LEGACY_ACCOUNT).value();
//    }

class AccountPubKey {
private:
    CExtPubKey pubkey;
public:
    AccountPubKey(CExtPubKey pubkey): pubkey(pubkey) {};

    const CExtPubKey& GetPubKey() const {
        return pubkey;
    }

    std::optional<CPubKey> DeriveExternal(uint32_t addrIndex) const;

    std::optional<CPubKey> DeriveInternal(uint32_t addrIndex) const;

    friend bool operator==(const AccountPubKey& a, const AccountPubKey& b)
    {
        return a.pubkey == b.pubkey;
    }
};

class AccountKey {
private:
    CExtKey accountKey;
    CExtKey external;
    CExtKey internal;

    AccountKey(CExtKey accountKeyIn, CExtKey externalIn, CExtKey internalIn):
            accountKey(accountKeyIn), external(externalIn), internal(internalIn) {}

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
    std::optional<CKey> DeriveExternalSpendingKey(uint32_t addrIndex) const;

    /**
     * Generate the key corresponding to the specified index at the "internal child"
     * level of the path for the account. This should probably only usually be
     * used at address index 0.
     */
    std::optional<CKey> DeriveInternalSpendingKey(uint32_t addrIndex = 0) const;

    /**
     * Return the public key associated with this spending key.
     */
    AccountPubKey GetAccountPubKey() const;

    friend bool operator==(const AccountKey& a, const AccountKey& b)
    {
        return a.accountKey == b.accountKey;
    }
};
