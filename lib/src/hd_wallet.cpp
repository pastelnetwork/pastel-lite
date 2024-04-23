// Copyright (c) 2018-2024 The Pastel core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <sodium.h>
#include "hd_wallet.h"
#include "utiltime.h"
#include "base58.h"
#include "pubkey.h"
#include "key.h"
#include "crypto/aes.h"
#include "hash.h"

string CHDWallet::SetupNewWallet(NetworkMode mode, const SecureString &password) {
    m_NetworkMode = mode;
    setNetworkParams(mode);

    // Generate new random master key and encrypt it using key derived from password
    string error;
    if (!setMasterKey(password, error)) {
        stringstream ss;
        ss << "Failed to set master key: " << error.c_str();
        throw runtime_error(ss.str());
    }

    // Generate new random mnemonic seed and encrypt it using master key
    auto bip44CoinType = m_NetworkParams->BIP44CoinType();
    MnemonicSeed seed = MnemonicSeed::Random(bip44CoinType, Language::English);
    if (!setEncryptedMnemonicSeed(seed, error)) {
        stringstream ss;
        ss << "Failed to set encrypted mnemonic seed: " << error.c_str();
        throw runtime_error(ss.str());
    }

    // verify that the seed can be decrypted
    auto decSeed = getDecryptedMnemonicSeed();
    if (!decSeed.has_value()) {
        throw runtime_error("Failed to get decrypted mnemonic seed");
    }
    return seed.GetMnemonic();
}

bool CHDWallet::setMasterKey(const SecureString &strPassphrase, string &error) noexcept {
    try {
        if (strPassphrase.empty()) {
            error = "Passphrase is empty";
            return false;
        }
        if (m_encryptedMasterKey.vchCryptedKey.size() == WALLET_CRYPTO_KEY_SIZE + AES_BLOCKSIZE) {// already set
            error = "Master key already set";
            return false;
        }
        if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE) { // already set
            error = "Master key already set";
            return false;
        }
        m_vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
        randombytes_buf(&m_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

        CMasterKey kMasterKey;
        kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
        randombytes_buf(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

        CCrypter crypter;
        int64_t nStartTime = GetTimeMillis();
        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        kMasterKey.nDeriveIterations = 2500000 / ((double) (GetTimeMillis() - nStartTime));

        nStartTime = GetTimeMillis();
        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                          kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 /
                                                                       ((double) (GetTimeMillis() - nStartTime))) / 2;
        if (kMasterKey.nDeriveIterations < 25000)
            kMasterKey.nDeriveIterations = 25000;

        if (!crypter.SetKeyFromPassphrase(strPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                          kMasterKey.nDerivationMethod)) {
            error = "Failed to set key from passphrase";
            return false;
        }
        if (!crypter.Encrypt(m_vMasterKey, kMasterKey.vchCryptedKey)) {
            error = "Failed to encrypt master key";
            return false;
        }
        m_encryptedMasterKey = kMasterKey;
    } catch (const exception &e) {
        error = e.what();
        return false;
    }
    return true;
}

bool CHDWallet::setEncryptedMnemonicSeed(const MnemonicSeed &seed, string &error) noexcept {
    try {
        // Use seed's fingerprint as IV
        auto seedFp = seed.Fingerprint();

        auto vchSeed = MnemonicSeed::Write(seed);

        vector<unsigned char> vchCryptedSecret;
        if (!CCrypter::EncryptSecret(m_vMasterKey, vchSeed, seedFp, vchCryptedSecret)) {
            error = "Failed to encrypt mnemonic seed";
            return false;
        }
        m_encryptedMnemonicSeed = make_pair(seedFp, vchCryptedSecret);
    } catch (const exception &e) {
        error = e.what();
        return false;
    }
    return true;
}

void CHDWallet::Lock() {
    memory_cleanse(&m_vMasterKey[0], m_vMasterKey.size());
    m_vMasterKey.clear();
}


void CHDWallet::Unlock(const SecureString &strPassphrase) {
    if (strPassphrase.empty())
        throw runtime_error("Passphrase is empty");
    if (m_encryptedMasterKey.vchCryptedKey.size() != WALLET_CRYPTO_KEY_SIZE + AES_BLOCKSIZE) // doesn't exist
        throw runtime_error("Master key doesn't exist");
    if (m_vMasterKey.size() == WALLET_CRYPTO_KEY_SIZE)  // already unlocked
        return;

    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(strPassphrase, m_encryptedMasterKey.vchSalt,
                                      m_encryptedMasterKey.nDeriveIterations, m_encryptedMasterKey.nDerivationMethod))
        throw runtime_error("Failed to set key from passphrase");
    if (!crypter.Decrypt(m_encryptedMasterKey.vchCryptedKey, m_vMasterKey))
        throw runtime_error("Failed to decrypt master key");
}

[[nodiscard]] optional<MnemonicSeed> CHDWallet::getDecryptedMnemonicSeed() const noexcept {
    if (m_encryptedMnemonicSeed.second.empty()) {
        return nullopt;
    }

    CKeyingMaterial vchSecret;

    // Use seed's fingerprint as IV
    if (CCrypter::DecryptSecret(m_vMasterKey, m_encryptedMnemonicSeed.second, m_encryptedMnemonicSeed.first,
                                vchSecret)) {
        auto seed = MnemonicSeed::Read(vchSecret);
        if (seed.Fingerprint() == m_encryptedMnemonicSeed.first) {
            return seed;
        }
    }
    return nullopt;
}

[[nodiscard]] string CHDWallet::MakeNewAddress() {
    auto size = m_addressIndexMap.size();
    return getAddressByIndex(size, true);
}

[[nodiscard]] string CHDWallet::GetAddress(uint32_t addrIndex) {
    return getAddressByIndex(addrIndex, false);
}

[[nodiscard]] string CHDWallet::getAddressByIndex(uint32_t addrIndex, bool bCreateNew) {
    if (m_indexAddressMap.contains(addrIndex)) {
        return m_indexAddressMap[addrIndex];
    }

    if (!bCreateNew) {
        throw runtime_error("Address not found");
    }

    auto key = GetAddressKey(addrIndex);

    // Get and encode public key
    const auto pubKey = key->GetPubKey();
    const auto keyID = pubKey.GetID();
    auto strPubKey = encodeAddress(keyID, m_NetworkParams);
    m_addressIndexMap[strPubKey] = addrIndex;
    m_indexAddressMap[addrIndex] = strPubKey;
    return strPubKey;
}


[[nodiscard]] string CHDWallet::GetNewLegacyAddress() {
    CKey secret;
    secret.MakeNewKey(true);

    const CPubKey newKey = secret.GetPubKey();
    if (!secret.VerifyPubKey(newKey)) {
        throw runtime_error("Failed to verify public key");
    }

    // Get and encode public key
    const CKeyID keyID = newKey.GetID();
    auto strPubKey = encodeAddress(keyID, m_NetworkParams);
    m_addressMapNonHD[strPubKey] = secret;
    return strPubKey;
}

optional<CKey> CHDWallet::GetAddressKey(const string &address) {
    auto addrIndex = m_addressIndexMap[address];
    return GetAddressKey(addrIndex);
}

optional<CKey> CHDWallet::GetAddressKey(uint32_t addrIndex) const {
    auto extKey = getExtKey(addrIndex);
    auto key = extKey.value().key;
    return key;
}

[[nodiscard]] string CHDWallet::GetWalletPubKey() {
    return GetPubKeyAt(m_NetworkParams->walletIDIndex);
}

[[nodiscard]] string CHDWallet::SignWithWalletKey(string message) {
    return SignWithKeyAt(m_NetworkParams->walletIDIndex, message);
}

[[nodiscard]] string CHDWallet::GetPubKeyAt(uint32_t addrIndex) {
    auto key = GetAddressKey(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to get key");
    }
    auto pubKey = key->GetPubKey();
    return EncodeBase58(pubKey.begin(), pubKey.end());
}

[[nodiscard]] string CHDWallet::SignWithKeyAt(uint32_t addrIndex, string message) {
    auto key = GetAddressKey(addrIndex);
    if (!key.has_value()) {
        throw runtime_error("Failed to get account key");
    }

    uint256 hash;
    CHash256().Write((unsigned char *) message.data(), message.size()).Finalize(hash.begin());
    v_uint8 vchSig;
    if (key.value().Sign(hash, vchSig)) {
        return EncodeBase58(vchSig);
    }
    return "";
}

[[nodiscard]] optional<CExtKey> CHDWallet::getExtKey(uint32_t addrIndex) const {
    if (IsLocked()) {
        throw runtime_error("Wallet is locked");
    }

    auto accountKey = getAccountKey();
    if (!accountKey.has_value()) {
        throw runtime_error("Failed to get account key");
    }
    auto extKey = accountKey.value().Derive(addrIndex);
    accountKey.value().Clear();
    if (!extKey.has_value()) {
        throw runtime_error("Failed to get new address");
    }
    return extKey;
}

[[nodiscard]] optional<AccountKey> CHDWallet::getAccountKey() const noexcept {
    auto seed = getDecryptedMnemonicSeed();
    if (!seed.has_value()) {
        return nullopt;
    }
    return AccountKey::MakeAccount(seed.value(), m_NetworkParams->bip44CoinType, 0);
}

void CHDWallet::setNetworkParams(NetworkMode mode) {
    switch (mode) {
        case NetworkMode::MAINNET:
            m_NetworkParams = new CMainnetParams();
            break;
        case NetworkMode::TESTNET:
            m_NetworkParams = new CTestnetParams();
            break;
        case NetworkMode::REGTEST:
            m_NetworkParams = new CRegtestParams();
            break;
        default:
            throw runtime_error("Invalid network mode");
    }
}

string CHDWallet::encodeAddress(const CKeyID &id, const CChainParams *network) noexcept {
    v_uint8 pubKey = network->Base58Prefix(CChainParams::Base58Type::PUBKEY_ADDRESS);
    pubKey.insert(pubKey.end(), id.begin(), id.end());
    return EncodeBase58Check(pubKey);
}

string CHDWallet::encodeExtPubKey(const CExtPubKey &key, const CChainParams *network) noexcept {
    v_uint8 data = network->Base58Prefix(CChainParams::Base58Type::EXT_PUBLIC_KEY);
    const size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    string ret = EncodeBase58Check(data);
    return ret;
}

CExtPubKey CHDWallet::decodeExtPubKey(const string &str, const CChainParams *network) noexcept {
    CExtPubKey key;
    v_uint8 data;
    if (DecodeBase58Check(str, data)) {
        const auto &prefix = network->Base58Prefix(CChainParams::Base58Type::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && equal(prefix.begin(), prefix.end(), data.begin()))
            key.Decode(data.data() + prefix.size());
    }
    return key;
}
