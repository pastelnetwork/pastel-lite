// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include "hd_wallet.h"
#include "utiltime.h"
#include "streams.h"

bool CHDWallet::SetMasterKey(const SecureString& strPassphrase)
{
    if (strPassphrase.empty())
        return false;
    if (m_encryptedMasterKey.vchCryptedKey.size() == WALLET_CRYPTO_KEY_SIZE)
        return false;
    if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE)
        return false;

    m_vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    randombytes_buf(&m_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    randombytes_buf(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(m_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    m_encryptedMasterKey = kMasterKey;
    return true;
}

bool CHDWallet::SetEncryptedMnemonicSeed(const MnemonicSeed& seed)
{
    // Use seed's fingerprint as IV
    auto seedFp = seed.Fingerprint();

    auto vchSeed = MnemonicSeed::Write(seed);

    std::vector<unsigned char> vchCryptedSecret;
    if (!CCrypter::EncryptSecret(m_vMasterKey, vchSeed, seedFp, vchCryptedSecret))
        return false;

    m_encryptedMnemonicSeed = std::make_pair(seedFp, vchCryptedSecret);
    return true;
}

[[nodiscard]] std::optional<MnemonicSeed> CHDWallet::GetDecryptedMnemonicSeed() const
{
    if (m_encryptedMnemonicSeed.second.empty()) {
        return std::nullopt;
    }

    CKeyingMaterial vchSecret;

    // Use seed's fingerprint as IV
    if (CCrypter::DecryptSecret(m_vMasterKey, m_encryptedMnemonicSeed.second, m_encryptedMnemonicSeed.first, vchSecret)) {
        auto seed = MnemonicSeed::Read(vchSecret);
        if (seed.Fingerprint() == m_encryptedMnemonicSeed.first) {
            return seed;
        }
    }
    return std::nullopt;
}
