// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include "hd_wallet.h"
#include "utiltime.h"
#include "streams.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <iostream>


bool CHDWallet::SetMasterKey(const SecureString& strPassphrase)
{
    // Assuming we have a salt; in real applications, it should be unique and random
    unsigned char salt[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};

    // Buffers for the derived key and IV
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    // Initialize OpenSSL's algorithms
    OpenSSL_add_all_algorithms();

    // Derive the key and IV from the password and salt
    int key_data_len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), salt,
                                      (unsigned char *)&strPassphrase[0], static_cast<int>(strPassphrase.size()), 1, key, iv);
    if(key_data_len != 32) { // For AES-256, the key length should be 32 bytes
        std::cerr << "Key length is incorrect." << std::endl;
    }

//    if (strPassphrase.empty())
//        return false;
//    if (m_encryptedMasterKey.vchCryptedKey.size() == WALLET_CRYPTO_KEY_SIZE)
//        return false;
//    if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE)
//        return false;
//
//    m_vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
//    randombytes_buf(&m_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);
//
//    CMasterKey kMasterKey;
//    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
//    randombytes_buf(&kMasterKey.vchSalt[0], WALLET_CRYPTO_KEY_SIZE);

//    CCrypter crypter;
//    int64_t nStartTime = GetTimeMillis();
//    crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
//    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

//    nStartTime = GetTimeMillis();
//    crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
//    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;
//
//    if (kMasterKey.nDeriveIterations < 25000)
//        kMasterKey.nDeriveIterations = 25000;
//
//    if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
//        return false;
//    if (!crypter.Encrypt(m_vMasterKey, kMasterKey.vchCryptedKey))
//        return false;

//    m_encryptedMasterKey = kMasterKey;
    return true;
}

bool CHDWallet::SetEncryptedMnemonicSeed(const MnemonicSeed& seed)
{
//    // Use seed's fingerprint as IV
//    auto seedFp = seed.Fingerprint();
//    CKeyingMaterial vchSecret = seed.EncryptMnemonicSeed();
//
//    std::vector<unsigned char> vchCryptedSecret;
//    if (!CCrypter::EncryptSecret(m_vMasterKey, vchSecret, seedFp, vchCryptedSecret))
//        return false;
//
//    // This will call into CWallet to store the crypted seed to disk
//    m_encryptedMnemonicSeed = std::make_pair(seedFp, vchCryptedSecret);
    return true;
}

[[nodiscard]] std::optional<MnemonicSeed> CHDWallet::GetMnemonicSeed() const
{
//    if (m_encryptedMnemonicSeed.second.empty()) {
//        return std::nullopt;
//    }
//
//    CKeyingMaterial vchSecret;
//
//    // Use seed's fingerprint as IV
//    if (CCrypter::DecryptSecret(m_vMasterKey, m_encryptedMnemonicSeed.second, m_encryptedMnemonicSeed.first, vchSecret)) {
//        CSecureDataStream ss(vchSecret, SER_NETWORK, PROTOCOL_VERSION);
//        auto seed = MnemonicSeed::Read(ss);
//        if (seed.Fingerprint() == m_encryptedMnemonicSeed.first) {
//            return seed;
//        }
//    }
    return std::nullopt;
}